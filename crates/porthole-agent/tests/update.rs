//! The update notifier, as a process, on a private session bus.
//!
//! Every test here starts `dbus-run-session`, points both
//! `DBUS_SESSION_BUS_ADDRESS` and `DBUS_SYSTEM_BUS_ADDRESS` at it, and runs
//! the real `porthole-agent` binary against stand-ins for the three services
//! it talks to: the notification server, the porthole helper, and
//! **PackageKit**. Nothing here installs, removes or upgrades a package --
//! the PackageKit below is test code that records what it was asked for and
//! answers.
//!
//! # A private bus is not an empty bus
//!
//! `dbus-run-session` starts a daemon with this machine's ordinary
//! configuration, which includes its service-activation directories. So a
//! name nothing on that bus owns is not a name that fails to resolve: it is a
//! name the daemon will happily **start a real program** for. Measured while
//! writing this file -- an earlier draft left `org.freedesktop.PackageKit`
//! unowned, and the private bus activated the machine's own session services
//! for it, gnome-software and the desktop portals along with them.
//!
//! Hence [`serve_packagekit`] in every test that reaches the check, including
//! the one whose subject is that no check happens: owning the name is what
//! makes the stand-in answer instead of the machine. This is the same hazard
//! `crates/porthole-cli/tests/cli.rs` documents for the helper, in its own
//! words, one bus over.
//!
//! # Stubs on `PATH`, and only builtins inside them
//!
//! The package manager is stubbed the other way, on `PATH`: `rpm` and `dnf`
//! here are shell scripts that exit with a chosen code, which is the whole of
//! what the check reads. The agent's `PATH` is the stub directory **alone**,
//! so those scripts may use shell builtins and nothing else -- an earlier
//! draft recorded that it had run with `touch`, which is not on that `PATH`,
//! so the marker file was never written and the assertion that the package
//! manager had *not* run passed without ever being able to fail. `echo` and
//! `>>` are builtins; that is what the marker uses now.
//!
//! # What is proven here
//!
//! That an available update becomes exactly one notification **per version**
//! and not one per check -- with the package manager provably run several
//! times in between; that pressing its button reaches PackageKit's own
//! `UpdatePackages` with the id PackageKit itself listed, and reaches the
//! porthole helper not at all; and that a machine whose owner has not
//! consented is not asked about, at all, with the package manager never run.
//!
//! # What is not
//!
//! No real PackageKit, no real polkit, and no package is ever installed. The
//! prompt a person would see, and the install behind it, are exercised by
//! nothing in this repository.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use porthole_core::ipc::{PATH as HELPER_PATH, PROTOCOL_VERSION, SERVICE as HELPER_SERVICE};
use porthole_core::update::{Consent, Settings};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

const NOTIFICATIONS_SERVICE: &str = "org.freedesktop.Notifications";
const NOTIFICATIONS_PATH: &str = "/org/freedesktop/Notifications";
const NOTIFICATIONS_INTERFACE: &str = "org.freedesktop.Notifications";

const PACKAGEKIT_SERVICE: &str = "org.freedesktop.PackageKit";
const PACKAGEKIT_PATH: &str = "/org/freedesktop/PackageKit";
/// One transaction path for every `CreateTransaction`. A real PackageKit
/// hands out a fresh one each time; this stand-in serves one object and names
/// it every time, which is all the agent does anything with.
const TRANSACTION_PATH: &str = "/porthole_test_transaction";

/// The action key the update notification's own button comes back as.
/// Spelled here because an integration test cannot reach into the binary's
/// own `update::UPDATE_NOW`; a rename there that is not made here turns the
/// click below into a click on a button nothing answers.
const UPDATE_NOW: &str = "update-now";

/// The package id the stand-in PackageKit lists as an available update.
/// `name;version;arch;data`, which is PackageKit's own shape.
const PORTHOLE_ID: &str = "porthole;0.2.0-1.fc44;x86_64;updates";

/// A package id for something else, listed alongside it. If the agent sent
/// this to `UpdatePackages` it would be updating a package nobody asked
/// about -- and `porthole-gui` starts with the same seven letters as
/// `porthole`, which is exactly the near miss a prefix match would fall for.
const OTHER_ID: &str = "porthole-gui;0.2.0-1.fc44;x86_64;updates";

const DEADLINE: Duration = Duration::from_secs(20);

/// A private bus, alive for as long as this value is -- the same shape
/// `tests/session.rs` uses, and for the same reason.
struct Bus {
    child: Child,
    address: String,
}

impl Bus {
    fn start() -> Bus {
        let mut child = Command::new("dbus-run-session")
            .args([
                "--",
                "sh",
                "-c",
                r#"echo "$DBUS_SESSION_BUS_ADDRESS"; exec cat >/dev/null"#,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-run-session is installed");
        let mut address = String::new();
        BufReader::new(child.stdout.take().expect("piped"))
            .read_line(&mut address)
            .expect("the session address");
        let address = address.trim().to_string();
        assert!(!address.is_empty(), "dbus-run-session printed no address");
        Bus { child, address }
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

/// The agent under test, killed however the test ends.
struct Agent {
    child: Child,
    stderr: tempfile::NamedTempFile,
}

impl Agent {
    fn journal(&self) -> String {
        let mut text = String::new();
        self.stderr
            .reopen()
            .expect("a read handle")
            .read_to_string(&mut text)
            .expect("readable");
        text
    }

    fn is_running(&mut self) -> bool {
        self.child.try_wait().expect("waitable").is_none()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Where `sleep` is, resolved on **this** process's `PATH`.
///
/// The stubs run with `PATH` set to the stub directory alone, so they may use
/// shell builtins and nothing else -- and no builtin waits. `sleep` is
/// therefore called from a stub by absolute path, found here, where a normal
/// `PATH` still exists.
fn sleep_binary() -> String {
    let out = Command::new("sh")
        .args(["-c", "command -v sleep"])
        .output()
        .expect("a shell to find `sleep` with");
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(
        !path.is_empty(),
        "no `sleep` on this machine's PATH, and a slow stub is how a test gets to act \
         while a check is still in flight"
    );
    path
}

/// Everything one test's filesystem needs: a directory of stub package
/// managers and a settings file of this test's own.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Fixture {
        refuse_a_release_build();
        let dir = tempfile::TempDir::new().expect("a temp dir");
        std::fs::create_dir_all(dir.path().join("bin")).expect("writable");
        Fixture { dir }
    }

    fn bin(&self) -> std::path::PathBuf {
        self.dir.path().join("bin")
    }

    fn settings(&self) -> std::path::PathBuf {
        self.dir.path().join("update.toml")
    }

    /// The file each stub appends a line to when it runs.
    ///
    /// A **count**, not a flag, and that is what lets a test say "the package
    /// manager was asked again" rather than only "it was asked once". It is
    /// also what makes the no-consent test's assertion able to fail: see this
    /// module's own doc comment for the draft in which it could not.
    fn marker(&self) -> std::path::PathBuf {
        self.dir.path().join("package-manager-runs")
    }

    /// How many times a stub package manager has run.
    fn runs(&self) -> usize {
        std::fs::read_to_string(self.marker())
            .map(|text| text.lines().count())
            .unwrap_or(0)
    }

    fn consent(&self, value: &str) {
        std::fs::write(self.settings(), format!("consent = \"{value}\"\n")).expect("writable");
    }

    /// Puts an executable `name` in the stub directory, running `body`.
    ///
    /// `body` may use shell **builtins only** -- see this module's own doc
    /// comment.
    fn stub(&self, name: &str, body: &str) {
        let path = self.bin().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("writable");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("writable");
    }

    /// The ordinary fixture: rpm owns porthole's binary, and dnf says an
    /// update is available. Each records that it ran, with builtins.
    fn an_rpm_machine_with_an_update(&self) {
        let marker = self.marker().display().to_string();
        // rpm(8) EXIT STATUS: "On success, 0 is returned" -- and for `-qf`,
        // success is the package that owns the file.
        self.stub("rpm", &format!("echo rpm >> '{marker}'\nexit 0"));
        // dnf5-check-upgrade(8): "DNF5 will exit with code 100 if updates are
        // available and list them; 0 if no updates are available."
        self.stub(
            "dnf",
            &format!(
                "echo dnf >> '{marker}'\n\
                 echo 'porthole.x86_64    0.2.0-1.fc44    porthole'\n\
                 exit 100"
            ),
        );
    }

    /// A Debian-packaged machine: `dpkg-query` claims porthole's binary, and
    /// there is no `rpm` on the stub `PATH` at all, so the ownership question
    /// reaches dpkg the way it would on a real one.
    ///
    /// No update stub of any kind, because none is ever run: apt documents no
    /// exit code meaning "an update is available", so the verdict is
    /// `NoContract` and porthole asks nothing further. That is the permanent
    /// state of every Debian and Arch machine, which is why it is worth a
    /// test of its own.
    fn a_dpkg_machine(&self) {
        let marker = self.marker().display().to_string();
        // dpkg-query(1): 0 is "the requested query was successfully
        // performed", which for `-S` is the package that owns the file.
        self.stub(
            "dpkg-query",
            &format!("echo dpkg-query >> '{marker}'\necho 'porthole: /usr/bin/porthole'\nexit 0"),
        );
    }

    /// The same machine, with an `rpm` that takes `seconds` to answer.
    ///
    /// It records that it ran **before** sleeping, so the marker appearing
    /// means the check has *started* rather than finished -- which is what
    /// lets a test do something while the check is genuinely in flight,
    /// rather than guessing at a window with a bare sleep of its own.
    fn a_slow_rpm_machine_with_an_update(&self, seconds: &str) {
        let marker = self.marker().display().to_string();
        let sleep = sleep_binary();
        self.stub(
            "rpm",
            &format!("echo rpm >> '{marker}'\n'{sleep}' {seconds}\nexit 0"),
        );
        self.stub(
            "dnf",
            &format!(
                "echo dnf >> '{marker}'\n\
                 echo 'porthole.x86_64    0.2.0-1.fc44    porthole'\n\
                 exit 100"
            ),
        );
    }

    fn start_agent(&self, bus: &Bus, interval_ms: u64) -> Agent {
        let stderr = tempfile::NamedTempFile::new().expect("a temp file for the agent's stderr");
        let child = Command::new(env!("CARGO_BIN_EXE_porthole-agent"))
            .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
            .env("DBUS_SYSTEM_BUS_ADDRESS", &bus.address)
            .env_remove("DBUS_STARTER_ADDRESS")
            .env_remove("DBUS_STARTER_BUS_TYPE")
            // The stub directory alone, so a package manager really installed
            // on the machine running these tests cannot answer instead of the
            // stub.
            .env("PATH", self.bin())
            .env("PORTHOLE_UPDATE_FILE", self.settings())
            .env("PORTHOLE_UPDATE_INTERVAL_MS", interval_ms.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr.reopen().expect("a second handle"))
            .spawn()
            .expect("the agent binary was built");
        Agent { child, stderr }
    }
}

/// Both `PORTHOLE_UPDATE_FILE` and `PORTHOLE_UPDATE_INTERVAL_MS` are honoured
/// in debug builds only, deliberately: a release binary must not take a
/// config path or its own timing from the environment.
///
/// What that means for a test is not that the overrides are lost -- it is
/// that the **real** ones are used instead: the invoking user's own
/// `~/.config/porthole/update.toml`, and a first check ninety seconds away
/// that no test here waits for. Every test in this file therefore carries
/// `#[cfg_attr(not(debug_assertions), ignore = ...)]`, and this is what makes
/// forgetting one a red test rather than a silent read of somebody's home
/// directory. The same arrangement `crates/porthole-cli/tests/cli.rs` uses,
/// for the same two reasons.
fn refuse_a_release_build() {
    #[cfg(not(debug_assertions))]
    panic!(
        "PORTHOLE_UPDATE_FILE and PORTHOLE_UPDATE_INTERVAL_MS are honoured in debug builds \
         only, so this release build would read the invoking user's own \
         ~/.config/porthole/update.toml and wait ninety seconds for a check no test here \
         waits for. This test needs `#[cfg_attr(not(debug_assertions), ignore = ...)]`."
    );
}

/// One `Notify` call, as the stand-in server received it.
#[derive(Debug, Clone)]
struct Shown {
    summary: String,
    body: String,
    actions: Vec<String>,
}

struct FakeNotifications {
    shown: Arc<Mutex<Vec<Shown>>>,
    id: u32,
}

#[zbus::interface(name = "org.freedesktop.Notifications")]
impl FakeNotifications {
    #[allow(clippy::too_many_arguments)]
    async fn notify(
        &self,
        _app_name: String,
        _replaces_id: u32,
        _app_icon: String,
        summary: String,
        body: String,
        actions: Vec<String>,
        _hints: HashMap<String, OwnedValue>,
        _expire_timeout: i32,
    ) -> u32 {
        self.shown.lock().expect("not poisoned").push(Shown {
            summary,
            body,
            actions,
        });
        self.id
    }
}

/// The porthole helper, exactly as far as the agent needs one at start-up --
/// and no further, on purpose. Every call it receives is recorded, so a test
/// can assert that **nothing about updating** ever reached it.
struct FakeHelper {
    calls: Arc<Mutex<Vec<String>>>,
}

#[zbus::interface(name = "com.jacopobriccola.Porthole1")]
impl FakeHelper {
    async fn list(&self) -> Vec<porthole_core::ipc::WireRule> {
        self.calls.lock().expect("not poisoned").push("List".into());
        Vec::new()
    }

    async fn protocol_version(&self) -> u32 {
        self.calls
            .lock()
            .expect("not poisoned")
            .push("ProtocolVersion".into());
        PROTOCOL_VERSION
    }
}

/// PackageKit's daemon object: hands out the one transaction path below.
struct FakePackageKit;

#[zbus::interface(name = "org.freedesktop.PackageKit")]
impl FakePackageKit {
    async fn create_transaction(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        OwnedObjectPath::try_from(TRANSACTION_PATH)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }
}

/// One PackageKit transaction, answering the two methods the agent uses and
/// emitting the signals a real one emits.
struct FakeTransaction {
    /// What `GetUpdates` lists.
    updates: Vec<String>,
    /// What `UpdatePackages` was asked to install, one entry per call.
    updated: Arc<Mutex<Vec<Vec<String>>>>,
}

#[zbus::interface(name = "org.freedesktop.PackageKit.Transaction")]
impl FakeTransaction {
    async fn get_updates(
        &self,
        _filter: u64,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        for id in &self.updates {
            // 11 is PK_INFO_ENUM_NORMAL; the agent reads the id, not this.
            Self::package(&emitter, 11, id, "porthole")
                .await
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        }
        // 1 is PK_EXIT_ENUM_SUCCESS.
        Self::finished(&emitter, 1, 0)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(())
    }

    async fn update_packages(
        &self,
        _transaction_flags: u64,
        package_ids: Vec<String>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        self.updated.lock().expect("not poisoned").push(package_ids);
        Self::finished(&emitter, 1, 0)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(())
    }

    #[zbus(signal)]
    async fn package(
        emitter: &SignalEmitter<'_>,
        info: u32,
        package_id: &str,
        summary: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn error_code(emitter: &SignalEmitter<'_>, code: u32, details: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn finished(emitter: &SignalEmitter<'_>, exit: u32, runtime: u32) -> zbus::Result<()>;
}

/// Poll until `f` answers, or give up after [`DEADLINE`].
async fn until<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = std::time::Instant::now() + DEADLINE;
    loop {
        if let Some(value) = f() {
            return value;
        }
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn serve_notifications(
    bus: &Bus,
    shown: Arc<Mutex<Vec<Shown>>>,
    id: u32,
) -> zbus::Connection {
    zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(NOTIFICATIONS_SERVICE)
        .unwrap()
        .serve_at(NOTIFICATIONS_PATH, FakeNotifications { shown, id })
        .unwrap()
        .build()
        .await
        .unwrap()
}

async fn serve_helper(bus: &Bus, calls: Arc<Mutex<Vec<String>>>) -> zbus::Connection {
    zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(HELPER_SERVICE)
        .unwrap()
        .serve_at(HELPER_PATH, FakeHelper { calls })
        .unwrap()
        .build()
        .await
        .unwrap()
}

/// Own `org.freedesktop.PackageKit` on the private bus.
///
/// **In every test that reaches the check, including the one about a check
/// that must not happen.** A name nothing owns is a name this machine's own
/// service files will start a real program for -- see this module's own doc
/// comment for what that was measured doing.
async fn serve_packagekit(
    bus: &Bus,
    updates: Vec<String>,
    updated: Arc<Mutex<Vec<Vec<String>>>>,
) -> zbus::Connection {
    zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(PACKAGEKIT_SERVICE)
        .unwrap()
        .serve_at(PACKAGEKIT_PATH, FakePackageKit)
        .unwrap()
        .serve_at(TRANSACTION_PATH, FakeTransaction { updates, updated })
        .unwrap()
        .build()
        .await
        .unwrap()
}

/// The notifications shown so far that are the update one.
fn update_notices(shown: &Arc<Mutex<Vec<Shown>>>) -> Vec<Shown> {
    shown
        .lock()
        .expect("not poisoned")
        .iter()
        .filter(|s| s.summary.contains("update is available"))
        .cloned()
        .collect()
}

#[tokio::test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_UPDATE_FILE and PORTHOLE_UPDATE_INTERVAL_MS are honoured in debug builds only, so a --release binary reads the invoking user's own settings and waits ninety seconds for a check this test does not wait for"
)]
async fn an_available_update_is_announced_once_per_version_and_not_once_per_check() {
    // The design's own verification item: the notification appears once per
    // version, "provato con due controlli consecutivi sulla stessa versione
    // disponibile". The interval below is short enough that several checks
    // run inside this test, and the run counter is what proves they did --
    // without it, "one notification" would also be what a single check
    // produces, and this would be asserting nothing about the second.
    let fixture = Fixture::new();
    fixture.consent("yes");
    fixture.an_rpm_machine_with_an_update();

    let bus = Bus::start();
    let shown = Arc::new(Mutex::new(Vec::new()));
    let _notifications = serve_notifications(&bus, shown.clone(), 77).await;
    let _helper = serve_helper(&bus, Arc::new(Mutex::new(Vec::new()))).await;
    let _packagekit = serve_packagekit(
        &bus,
        vec![PORTHOLE_ID.to_string()],
        Arc::new(Mutex::new(Vec::new())),
    )
    .await;

    let mut agent = fixture.start_agent(&bus, 150);
    until("the agent to start listening", || {
        agent.journal().contains("listening for uid").then_some(())
    })
    .await;

    let notice = until("the update notification", || {
        update_notices(&shown).first().cloned()
    })
    .await;
    assert!(
        notice.body.contains("0.2.0-1.fc44"),
        "the version the package manager listed is what a person is told: {notice:?}"
    );
    assert!(
        notice.actions.iter().any(|a| a == UPDATE_NOW),
        "PackageKit answers on this bus, so the notification carries its button: {notice:?}"
    );

    // The package manager really is asked again, several times over.
    let first_round = fixture.runs();
    assert!(first_round > 0, "the stub package manager never ran at all");
    until("the package manager to be asked again", || {
        (fixture.runs() > first_round).then_some(())
    })
    .await;

    assert_eq!(
        update_notices(&shown).len(),
        1,
        "one notification per version, however many checks ({} runs of the package \
         manager): {:?}",
        fixture.runs(),
        update_notices(&shown)
    );
    assert!(agent.is_running(), "{}", agent.journal());
}

#[tokio::test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_UPDATE_FILE and PORTHOLE_UPDATE_INTERVAL_MS are honoured in debug builds only, so a --release binary reads the invoking user's own settings and waits ninety seconds for a check this test does not wait for"
)]
async fn pressing_update_hands_the_package_to_packagekit_and_nothing_to_the_helper() {
    // The security property the whole design turns on, asserted rather than
    // asserted about: the update goes to PackageKit, and the privileged
    // porthole helper -- which accepts firewall operations and never a
    // command from a client -- is asked nothing about it.
    let fixture = Fixture::new();
    fixture.consent("yes");
    fixture.an_rpm_machine_with_an_update();

    let bus = Bus::start();
    let shown = Arc::new(Mutex::new(Vec::new()));
    let notification_id = 91;
    let notifications = serve_notifications(&bus, shown.clone(), notification_id).await;
    let helper_calls = Arc::new(Mutex::new(Vec::new()));
    let _helper = serve_helper(&bus, helper_calls.clone()).await;
    let updated = Arc::new(Mutex::new(Vec::new()));
    let _packagekit = serve_packagekit(
        &bus,
        vec![OTHER_ID.to_string(), PORTHOLE_ID.to_string()],
        updated.clone(),
    )
    .await;

    let mut agent = fixture.start_agent(&bus, 150);
    until("the update notification", || {
        update_notices(&shown).first().cloned()
    })
    .await;

    // The click.
    notifications
        .emit_signal(
            None::<()>,
            NOTIFICATIONS_PATH,
            NOTIFICATIONS_INTERFACE,
            "ActionInvoked",
            &(notification_id, UPDATE_NOW),
        )
        .await
        .unwrap();

    let asked = until("PackageKit to be asked to update", || {
        updated.lock().expect("not poisoned").first().cloned()
    })
    .await;
    assert_eq!(
        asked,
        vec![PORTHOLE_ID.to_string()],
        "exactly the id PackageKit itself listed for porthole -- not the one it listed for \
         another package whose name starts the same way, and not a bare name"
    );

    // And the helper heard nothing about any of it. The two calls it may
    // legitimately receive are the ones every agent makes at start-up.
    let calls = helper_calls.lock().expect("not poisoned").clone();
    for call in &calls {
        assert!(
            call == "List" || call == "ProtocolVersion",
            "the privileged helper must have nothing to do with updating, and it was \
             asked: {calls:?}"
        );
    }
    assert!(agent.is_running(), "{}", agent.journal());
}

#[tokio::test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_UPDATE_FILE and PORTHOLE_UPDATE_INTERVAL_MS are honoured in debug builds only, so a --release binary reads the invoking user's own settings and waits ninety seconds for a check this test does not wait for"
)]
async fn without_consent_the_package_manager_is_never_even_run() {
    // "Il controllo periodico è attivo solo dopo che l'utente ha risposto."
    // Proven by a run counter that stays at zero rather than by the absence
    // of a notification: a check that ran and found nothing to say would
    // leave no notification either, and those are not the same fact.
    let fixture = Fixture::new();
    // No settings file at all: the state of a machine nobody has asked.
    fixture.an_rpm_machine_with_an_update();

    let bus = Bus::start();
    let shown = Arc::new(Mutex::new(Vec::new()));
    let _notifications = serve_notifications(&bus, shown.clone(), 55).await;
    let _helper = serve_helper(&bus, Arc::new(Mutex::new(Vec::new()))).await;
    let _packagekit = serve_packagekit(
        &bus,
        vec![PORTHOLE_ID.to_string()],
        Arc::new(Mutex::new(Vec::new())),
    )
    .await;

    let mut agent = fixture.start_agent(&bus, 150);
    until("the agent to start listening", || {
        agent.journal().contains("listening for uid").then_some(())
    })
    .await;

    // The control on the assertions below: a second agent, on a machine that
    // *has* consented, with the same stubs and the same interval, runs the
    // package manager. Until that is seen, an untouched counter proves
    // nothing -- it is equally what a stub that never worked leaves behind,
    // which is exactly the shape this file's own first draft failed in.
    //
    // **On a bus of its own**, and that is not tidiness. Both agents would
    // otherwise share this bus's one notification stand-in, so the control's
    // own notification would land in `shown` and the "nothing was shown"
    // assertion below would be reading the wrong agent's output -- measured,
    // because that is what the first version of this test did.
    let control_bus = Bus::start();
    let consenting = Fixture::new();
    consenting.consent("yes");
    consenting.an_rpm_machine_with_an_update();
    let mut second = consenting.start_agent(&control_bus, 150);
    until(
        "the package manager to run for a consenting machine",
        || (consenting.runs() > 0).then_some(()),
    )
    .await;

    // Both agents started within moments of each other with the same
    // interval, so by the time the consenting one has been round its check
    // the other has had at least as long to go round its own.
    assert_eq!(
        fixture.runs(),
        0,
        "no consent, so no package manager may be run at all -- and one was"
    );
    assert!(
        update_notices(&shown).is_empty(),
        "nor anything shown: {:?}",
        update_notices(&shown)
    );

    assert!(agent.is_running(), "{}", agent.journal());
    assert!(second.is_running(), "{}", second.journal());
}

#[tokio::test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_UPDATE_FILE and PORTHOLE_UPDATE_INTERVAL_MS are honoured in debug builds only, so a --release binary reads the invoking user's own settings and waits ninety seconds for a check this test does not wait for"
)]
async fn a_packaging_that_documents_no_exit_code_says_so_in_the_journal() {
    // The state a consenting Debian or Arch machine is in **permanently**:
    // apt and pacman document no exit code meaning "an update is available",
    // so the check reaches `NoContract` every day and, by design, puts
    // nothing on screen -- a daily "could not find out" would be a daily
    // interruption reporting no news.
    //
    // What it must not be is *invisible* as well as inert. Without the
    // journal line, such a machine spawns `dpkg-query` daily forever, shows
    // nothing, logs nothing, and the first question anyone debugging it would
    // ask -- why do I never see an update? -- has no answer anywhere on the
    // machine.
    let fixture = Fixture::new();
    fixture.consent("yes");
    fixture.a_dpkg_machine();

    let bus = Bus::start();
    let shown = Arc::new(Mutex::new(Vec::new()));
    let _notifications = serve_notifications(&bus, shown.clone(), 44).await;
    let _helper = serve_helper(&bus, Arc::new(Mutex::new(Vec::new()))).await;
    let _packagekit = serve_packagekit(
        &bus,
        vec![PORTHOLE_ID.to_string()],
        Arc::new(Mutex::new(Vec::new())),
    )
    .await;

    let mut agent = fixture.start_agent(&bus, 150);
    let journal = until("the check to report what it could not find out", || {
        let journal = agent.journal();
        journal
            .contains("did not find out whether an update is available")
            .then_some(journal)
    })
    .await;

    // And the line carries the reason, naming the documentation, rather than
    // a bare "could not find out" that sends the reader nowhere.
    assert!(
        journal.contains("apt-get(8)"),
        "the journal line has to say why, and name what says so: {journal}"
    );
    // The package manager really was asked -- so this is the answer to a
    // question that was put, not a line printed instead of asking.
    assert!(
        fixture.runs() > 0,
        "dpkg-query was never run, so nothing established the packaging at all"
    );
    // Nothing on screen, which is the other half of the design's decision.
    assert!(
        update_notices(&shown).is_empty(),
        "a packaging that cannot answer must not produce a notification: {:?}",
        update_notices(&shown)
    );
    assert!(agent.is_running(), "{journal}");
}

#[tokio::test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_UPDATE_FILE and PORTHOLE_UPDATE_INTERVAL_MS are honoured in debug builds only, so a --release binary reads the invoking user's own settings and waits ninety seconds for a check this test does not wait for"
)]
async fn a_consent_withdrawn_while_a_check_is_in_flight_is_not_reverted() {
    // The one setting porthole may not own. A check reads the settings before
    // it starts asking package managers, and the asking can take seconds --
    // this file's own stubs make that literal. If what it wrote afterwards
    // were the copy it read before, a `porthole update --disable` issued
    // inside that window would be reverted to `yes`, silently and for good,
    // and the daily checks would carry on against an instruction the person
    // had just given.
    let fixture = Fixture::new();
    fixture.consent("yes");
    fixture.a_slow_rpm_machine_with_an_update("2");

    let bus = Bus::start();
    let shown = Arc::new(Mutex::new(Vec::new()));
    let _notifications = serve_notifications(&bus, shown.clone(), 33).await;
    let _helper = serve_helper(&bus, Arc::new(Mutex::new(Vec::new()))).await;
    let _packagekit = serve_packagekit(
        &bus,
        vec![PORTHOLE_ID.to_string()],
        Arc::new(Mutex::new(Vec::new())),
    )
    .await;

    let mut agent = fixture.start_agent(&bus, 150);
    until("the agent to start listening", || {
        agent.journal().contains("listening for uid").then_some(())
    })
    .await;

    // The check is now genuinely in flight: `rpm` has recorded itself and is
    // sleeping, and the agent read the settings before it spawned it.
    until("the check to be in flight", || {
        (fixture.runs() > 0).then_some(())
    })
    .await;

    // Exactly what `porthole update --disable` writes, through the same type
    // it writes it with -- not a hand-rolled file, so a change to how consent
    // is stored reaches this test rather than going round it.
    let mut withdrawn = Settings::load(&fixture.settings());
    withdrawn.set_consent(Consent::No);
    withdrawn.save(&fixture.settings()).expect("writable");
    assert_eq!(
        Settings::load(&fixture.settings()).consent(),
        Consent::No,
        "the withdrawal has to have landed before the check finishes, or this test is \
         about nothing"
    );

    // Long enough for the sleeping `rpm` to answer, the check to finish and
    // do whatever it does with its answer, and another tick to come round.
    tokio::time::sleep(Duration::from_secs(3)).await;

    assert_eq!(
        Settings::load(&fixture.settings()).consent(),
        Consent::No,
        "a check that was already running wrote back the consent it had read before it \
         started, reverting an answer the person gave while it ran"
    );
    // And it said nothing either: the answer arrived after the question
    // stopped being one porthole had leave to ask.
    assert!(
        update_notices(&shown).is_empty(),
        "consent was withdrawn while the check ran, and it announced anyway: {:?}",
        update_notices(&shown)
    );
    assert!(agent.is_running(), "{}", agent.journal());
}
