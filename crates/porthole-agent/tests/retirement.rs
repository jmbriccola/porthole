//! The real agent, the real helper, and a real retirement between them.
//!
//! `tests/session.rs` drives this binary against a stand-in helper: forty
//! lines of test code that answer whatever a case wants answered. Nothing in
//! it can produce the one thing this file is about, because a helper that is
//! *between lives* is not an answer a stand-in gives -- it is a bus name
//! changing hands while a call is in the air, and only a helper that really
//! decides to go and a bus that really activates a fresh one produce it.
//!
//! So this file does what `crates/porthole-helper/tests/idle_exit.rs` does:
//! a private `dbus-daemon` with a `<servicedir>` of its own, an activation
//! file naming a wrapper script, and the real `porthole-helper` binary behind
//! it. Both `DBUS_SESSION_BUS_ADDRESS` and `DBUS_SYSTEM_BUS_ADDRESS` point at
//! that one daemon, so the agent's system-bus connection reaches the helper
//! and its session-bus connection reaches the stand-in notification service
//! here -- the same arrangement `session.rs` uses, with a real helper in
//! place of the fake one.
//!
//! # The window, entered on purpose
//!
//! A helper that has already gone is not a failure for anybody: the name is
//! unowned, the next call activates a fresh instance and is served first
//! time. The two failures a client has to survive live in windows that are
//! sub-millisecond in production:
//!
//! - between the decision to retire and the release of the name, where the
//!   leaving instance still owns it and answers
//!   `com.jacopobriccola.Porthole.Retiring`;
//! - around the exit itself, where a request already routed to the leaving
//!   instance loses its reply and the bus answers `NoReply`.
//!
//! `PORTHOLE_IDLE_PRERELEASE_MS` widens the first one deliberately -- see
//! `porthole_helper::retire::PRERELEASE_ENV`, which exists for exactly this
//! and says why hunting the window with load is worse than useless. Every
//! test here enters it on purpose, and every test here then *proves* it did:
//! see [`HELD_AT_LEAST`], without which a run whose call arrived a moment too
//! late would be served first time, retry nothing, and pass.
//!
//! # What this proves, and what it does not
//!
//! It proves that `porthole-agent`, as a process, survives a real
//! retirement: a `Reopen` click that lands inside the window reopens the
//! port instead of putting a failure on the screen, and an agent that starts
//! inside it still wakes a helper instead of listening to one nobody woke.
//!
//! The **other** of the two failures, `NoReply`, is not driven here, and
//! nothing in this repository drives it against a real helper. It is the last
//! instant of an exit and there is no knob that widens it:
//! `PORTHOLE_IDLE_SETTLE_MS` widens the window *after* the release, where
//! calls are routed to a fresh instance and nothing is lost, and
//! `idle_exit.rs`'s own load arm reports `0 retried` on an ordinary run --
//! forty rounds across a dozen real retirements without one call falling in a
//! window that narrow. What covers `NoReply` is `porthole_core::ipc`'s unit
//! test of the retry, on the error the bus itself sends, plus the fact that
//! the two names go through one predicate and one retry. That is stated here
//! rather than left to be assumed from a green tick.
//!
//! What it does not touch is a real
//! notification daemon (the stand-in below answers `Notify` and emits
//! `ActionInvoked`; it draws nothing), polkit (a `--session` helper
//! authorizes everything, by construction -- see `porthole_helper::main`),
//! or a real firewall.
//!
//! # What this file asks of the machine running it
//!
//! **No firewall, no system bus, no root, and nothing outside its own
//! temporary directory.** Every helper it activates is started by a wrapper
//! script that puts a stub `firewall-cmd` and a stub `ip` in front of its
//! `PATH` and points `PORTHOLE_STATE_FILE` at a temporary file. The stub
//! answers as firewalld and keeps its "rules" in a file under that same
//! directory, so an `open` here adds a line to a text file and a `close`
//! removes it. There is no arrangement of these tests in which anything
//! reaches a real ruleset.
//!
//! # Nothing here skips
//!
//! `porthole-helper --session` exists only in a debug build, and so do the
//! grace and prerelease overrides, so a `cargo test --release` reports these
//! `ignored`, by name. Everything else is an assertion.

use porthole_core::ipc::{PortholeProxy, SERVICE};
use std::collections::HashMap;
use std::io::{BufRead as _, Read as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use zbus::zvariant::OwnedValue;

/// The zone the stub firewalld answers with. Not a real zone name on any
/// machine, so a rule handle built here could not collide with one from a
/// firewall that is actually installed.
const STUB_ZONE: &str = "porthole-agent-retirement-test";

/// How long anything here waits before believing the opposite. Generous: a
/// parallel `cargo test` on a loaded machine is not the thing under test.
const WITHIN: Duration = Duration::from_secs(30);

const NOTIFICATIONS_SERVICE: &str = "org.freedesktop.Notifications";
const NOTIFICATIONS_PATH: &str = "/org/freedesktop/Notifications";
const NOTIFICATIONS_INTERFACE: &str = "org.freedesktop.Notifications";

/// The port every test here opens and closes. Nothing binds it; the stub
/// firewall is a text file.
const PORT: u16 = 5173;
const SUBNET: &str = "10.10.10.0/24";

/// `CARGO_BIN_EXE_<name>` resolves only for a binary in this test's own
/// package. `porthole-helper` is a sibling package, and `cargo test` puts
/// every workspace binary in one `target/<profile>/` directory, so it is
/// found beside this package's own -- the same means
/// `porthole-cli/tests/helper_e2e.rs` uses, written out there.
fn helper_bin() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_porthole-agent")).with_file_name("porthole-helper")
}

fn write_executable(path: &Path, body: &str) {
    std::fs::write(path, body).expect("writing a script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// A private `dbus-daemon` that can activate `com.jacopobriccola.Porthole`,
/// and everything the helper it activates is pointed at.
struct Bus {
    daemon: Child,
    address: String,
    dir: TempDir,
}

impl Drop for Bus {
    fn drop(&mut self) {
        // The daemon first: it is what would otherwise activate another
        // helper while the temporary directory is being removed.
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

impl Bus {
    /// A bus that will activate a helper with `grace_ms` of idleness before
    /// it retires and `prerelease_ms` between deciding to and giving up the
    /// name -- the window every test here places a call inside.
    fn start(grace_ms: u64, prerelease_ms: u64) -> Bus {
        // Shallow, because a unix socket path is capped at 108 bytes and
        // `dbus-daemon` refuses to start with "Socket name too long".
        let dir = TempDir::new().expect("a temporary directory");
        let bin = dir.path().join("bin");
        let services = dir.path().join("services");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&services).unwrap();

        // The stub firewalld's whole ruleset. Unlike `idle_exit.rs`'s, this
        // one is *written* by the stub as well as read by it: these tests
        // open and close a port for real, through the helper's own firewalld
        // backend, and that backend reads the rule list back after an add to
        // learn the exact string firewalld normalised its request to. A stub
        // that only listed a fixed file would fail that read-back and every
        // `open` here with it.
        std::fs::write(dir.path().join("rich-rules"), "").unwrap();

        write_executable(
            &bin.join("firewall-cmd"),
            &format!(
                "#!/bin/sh\n\
                 rules='{rules}'\n\
                 for arg in \"$@\"; do\n\
                 case \"$arg\" in\n\
                 --version) echo '2.4.4'; exit 0 ;;\n\
                 --state) echo 'running'; exit 0 ;;\n\
                 --get-default-zone) echo '{STUB_ZONE}'; exit 0 ;;\n\
                 --get-zone-of-interface=*) echo '{STUB_ZONE}'; exit 0 ;;\n\
                 --list-rich-rules) cat \"$rules\"; exit 0 ;;\n\
                 --add-rich-rule=*)\n\
                 printf '%s\\n' \"${{arg#--add-rich-rule=}}\" >>\"$rules\"\n\
                 echo success; exit 0 ;;\n\
                 --remove-rich-rule=*)\n\
                 grep -Fxv \"${{arg#--remove-rich-rule=}}\" \"$rules\" >\"$rules.new\" || true\n\
                 mv \"$rules.new\" \"$rules\"\n\
                 echo success; exit 0 ;;\n\
                 esac\n\
                 done\n\
                 echo \"agent-retirement stub firewall-cmd: unhandled $*\" >&2\n\
                 exit 2\n",
                rules = dir.path().join("rich-rules").display(),
            ),
        );
        write_executable(
            &bin.join("ip"),
            "#!/bin/sh\n\
             case \"$*\" in\n\
             *'route show default'*)\n\
             echo '[{\"dst\":\"default\",\"dev\":\"wlo1\",\"metric\":600}]' ;;\n\
             *'addr show'*)\n\
             echo '[{\"ifindex\":2,\"ifname\":\"wlo1\",\"addr_info\":[{\"family\":\"inet\",\
             \"local\":\"10.10.10.119\",\"prefixlen\":24,\"scope\":\"global\"}]}]' ;;\n\
             *) echo \"agent-retirement stub ip: unhandled $*\" >&2; exit 2 ;;\n\
             esac\n",
        );

        // The environment lives in this wrapper rather than in the bus
        // daemon's own, so what an activated helper is given does not depend
        // on what a bus daemon happens to pass on to its children -- and so
        // that every instance's stderr lands in one log this file can read.
        let wrapper = dir.path().join("activate-helper");
        write_executable(
            &wrapper,
            &format!(
                "#!/bin/sh\n\
                 export PATH='{bin}':\"$PATH\"\n\
                 export PORTHOLE_STATE_FILE='{state}'\n\
                 export PORTHOLE_IDLE_GRACE_MS={grace_ms}\n\
                 export PORTHOLE_IDLE_SETTLE_MS=50\n\
                 export PORTHOLE_IDLE_PRERELEASE_MS={prerelease_ms}\n\
                 export PORTHOLE_IDLE_EXIT=1\n\
                 exec '{helper}' --session >>'{log}' 2>&1\n",
                bin = bin.display(),
                state = dir.path().join("state.json").display(),
                helper = helper_bin().display(),
                log = dir.path().join("helper.log").display(),
            ),
        );
        std::fs::write(dir.path().join("helper.log"), "").unwrap();

        std::fs::write(
            services.join("com.jacopobriccola.Porthole.service"),
            format!(
                "[D-BUS Service]\nName={SERVICE}\nExec={}\n",
                wrapper.display()
            ),
        )
        .unwrap();

        let config = dir.path().join("bus.conf");
        std::fs::write(
            &config,
            format!(
                r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:tmpdir={dir}</listen>
  <auth>EXTERNAL</auth>
  <servicedir>{services}</servicedir>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_type="method_call"/>
    <allow send_type="signal"/>
    <allow send_requested_reply="true" send_type="method_return"/>
    <allow send_requested_reply="true" send_type="error"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
  </policy>
</busconfig>
"#,
                dir = dir.path().display(),
                services = services.display(),
            ),
        )
        .unwrap();

        // Asserted, not skipped. `dbus-broker` cannot stand in: this needs a
        // daemon that reads a `busconfig` file with a `<servicedir>` in it,
        // and skipping would report success on an activation nothing had
        // performed.
        let mut daemon = Command::new("dbus-daemon")
            .arg(format!("--config-file={}", config.display()))
            .arg("--print-address")
            .arg("--nofork")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "`dbus-daemon` would not run ({e}). It is required, not optional: it is \
                     the only bus here that can *activate* porthole-helper, and activation is \
                     what makes a retirement something a client can survive. Install it \
                     (Fedora: `dbus-daemon`, Debian: `dbus`, Arch: `dbus`)."
                )
            });
        let mut address = String::new();
        std::io::BufReader::new(daemon.stdout.take().expect("piped"))
            .read_line(&mut address)
            .expect("the private bus prints its address");
        let address = address.trim().to_string();
        assert!(!address.is_empty(), "dbus-daemon printed no address");

        Bus {
            daemon,
            address,
            dir,
        }
    }

    async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .expect("an address zbus can parse")
            .build()
            .await
            .expect("the private bus accepts a client")
    }

    async fn proxy(&self) -> PortholeProxy<'static> {
        PortholeProxy::new(&self.connect().await)
            .await
            .expect("the published proxy")
    }

    /// Everything every activated helper has written to its stderr, in order.
    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("helper.log")).unwrap_or_default()
    }

    /// How many helper processes this bus has activated. Counted from the one
    /// line a helper writes the instant it owns the name, so it counts
    /// instances that actually served, not processes that started.
    fn activations(&self) -> usize {
        self.log()
            .lines()
            .filter(|l| l.contains(&format!("serving {SERVICE}")))
            .count()
    }
}

/// The agent under test, killed however the test ends.
struct Agent {
    child: Child,
    stderr: tempfile::NamedTempFile,
}

impl Agent {
    fn start(bus: &Bus) -> Agent {
        let stderr = tempfile::NamedTempFile::new().expect("a temp file for the agent's stderr");
        let child = Command::new(env!("CARGO_BIN_EXE_porthole-agent"))
            // Both buses are this one private bus. The agent asks for the
            // system bus by name and gets it here, which is the only reason
            // a test can stand a real helper in front of it at all.
            .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
            .env("DBUS_SYSTEM_BUS_ADDRESS", &bus.address)
            .env_remove("DBUS_STARTER_ADDRESS")
            .env_remove("DBUS_STARTER_BUS_TYPE")
            // The agent replaces itself when the helper speaks a *newer*
            // protocol than it does. It cannot here -- both come from this
            // one build -- and if that ever stopped being true, a test that
            // re-executed the agent mid-run would be measuring something
            // else entirely. This makes that a refusal with a journal line
            // rather than a silent re-execution.
            .env("PORTHOLE_AGENT_REEXECED", u32::MAX.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr.reopen().expect("a second handle on the temp file"))
            .spawn()
            .expect("the agent binary was built");
        Agent { child, stderr }
    }

    fn journal(&self) -> String {
        let mut text = String::new();
        self.stderr
            .reopen()
            .expect("a read handle")
            .read_to_string(&mut text)
            .expect("readable");
        text
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
    /// Handed back as the notification id, and what a test then sends
    /// `ActionInvoked` for.
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

/// Poll until `f` answers, or fail after [`WITHIN`] saying what was waited
/// for and what the helper had said by then.
async fn until<T>(what: &str, bus: &Bus, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + WITHIN;
    loop {
        if let Some(value) = f() {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}\n--- the helper's log ---\n{}",
            bus.log()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// How wide every test here makes the prerelease window, and the floor a
/// call that really entered it must have waited.
///
/// The floor is what stops these tests passing on having measured nothing.
/// A call refused by a leaving instance is *held* until the name is released
/// -- `Retirement::admit` answers only then, so that the client's retry
/// cannot land back on the instance it is leaving -- so entering the window
/// costs the caller whatever is left of it. A call that arrived after the
/// window closed pays nothing but a cold activation, measured at ~250 ms in
/// a container. Four seconds against a floor of one and a half is not a
/// lottery between those two; it is the difference between them, and it is
/// the one observable consequence a client-side retry leaves behind.
const PRERELEASE: u64 = 4000;
const HELD_AT_LEAST: Duration = Duration::from_millis(1500);

/// Wait until an activated helper has taken the decision to retire and is
/// sitting in the prerelease window -- the only moment at which a request is
/// refused, and therefore the only moment at which asking again is what
/// saves one.
///
/// The helper prints "giving up" at the top of its retirement sequence,
/// *before* the prerelease sleep, so this returns with the whole of that
/// window still ahead.
async fn until_it_has_decided_to_go(bus: &Bus) {
    until("the helper to decide to retire", bus, || {
        bus.log().contains("giving up").then_some(())
    })
    .await;
    assert!(
        !bus.log().contains("nothing is left to answer"),
        "the helper had already finished retiring, so a call now would be served by a \
         fresh instance first time and nothing here would be retried:\n{}",
        bus.log()
    );
}

/// Fail unless `waited` is long enough to have been spent inside the window.
///
/// Not a performance assertion and not a timeout: see [`HELD_AT_LEAST`]. It
/// is the guard that makes the assertion beside it mean something, and it is
/// here rather than written out twice because both tests need exactly it.
fn was_held_by_the_leaving_instance(what: &str, waited: Duration, bus: &Bus) {
    assert!(
        waited >= HELD_AT_LEAST,
        "{what} came back in {waited:?}, which is too fast to have been refused \
         and held by an instance that was still leaving -- the window had \
         already closed, a fresh helper served the first attempt, and nothing \
         here was ever asked twice. This test measured nothing.\n{}",
        bus.log()
    );
}

/// The agent's own uid, which is this process's: the helper records the uid
/// that opened a rule, and the agent announces a close only for its own.
fn our_uid() -> u32 {
    // SAFETY: getuid takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    not(debug_assertions),
    ignore = "`porthole-helper --session` and the retirement overrides are debug-only"
)]
async fn a_reopen_clicked_while_the_helper_is_retiring_reopens_the_port() {
    // The click this whole change is about, and the reason it is the agent's
    // problem more than anybody's. A notification offering `Reopen` exists
    // *because* a rule stopped being open -- which is also what can leave the
    // helper holding nothing, and a helper holding nothing retires. So the
    // ordinary life of that button is: a port closes, a person reads the
    // notification, the helper's grace runs out while they are reading it,
    // and the click lands on an instance that is on its way out.
    //
    // Before the retry, that click produced "Could not reopen port 5173/tcp"
    // with the helper's own refusal underneath it, about a helper that was
    // perfectly well and one call away.
    let bus = Bus::start(700, PRERELEASE);
    let uid = our_uid();

    let shown = Arc::new(Mutex::new(Vec::new()));
    let notification_id = 42;
    let notifications = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(NOTIFICATIONS_SERVICE)
        .unwrap()
        .serve_at(
            NOTIFICATIONS_PATH,
            FakeNotifications {
                shown: shown.clone(),
                id: notification_id,
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let agent = Agent::start(&bus);
    let proxy = bus.proxy().await;
    until("the agent to be listening", &bus, || {
        agent.journal().contains("listening for uid").then_some(())
    })
    .await;

    // A real rule, opened by the real helper through the stub firewall.
    // `0` seconds is until-reboot, which is what keeps `porthole_core::expiry`
    // -- and therefore `systemd-run` -- out of this entirely.
    let opened = proxy
        .open(PORT, "tcp", SUBNET, 0)
        .await
        .unwrap_or_else(|e| panic!("the helper would not open a port: {e}\n{}", bus.log()));
    assert_eq!(
        opened.uid, uid,
        "the rule must be this user's to be announced"
    );

    // Closed as the expiry timer closes one, which is the reason whose
    // notification carries a `Reopen` button. Nothing here is a timer: the
    // flag is a claim the client makes about itself, and the helper accepts
    // it -- see `porthole_helper::service::Porthole::close_by_id`.
    proxy
        .close_by_id(&opened.id, true, false)
        .await
        .expect("the helper closes what it opened");

    let notification = until("the close to be announced on screen", &bus, || {
        shown.lock().unwrap().first().cloned()
    })
    .await;
    assert!(
        notification.summary.contains("5173/tcp"),
        "{notification:?}"
    );
    assert!(
        notification.body.contains("expired"),
        "the reason decides which notification this is and whether it offers a \
         button at all: {notification:?}"
    );
    assert_eq!(
        notification.actions,
        vec!["reopen".to_string(), "Reopen".to_string()],
        "without the button there is nothing for this test to click"
    );

    // Nothing is open now, so the grace starts running. Wait until the helper
    // has decided to go and is holding the door.
    until_it_has_decided_to_go(&bus).await;
    let activations_before = bus.activations();
    assert_eq!(activations_before, 1, "log:\n{}", bus.log());

    // The click, inside the window.
    let clicked = Instant::now();
    notifications
        .emit_signal(
            None::<()>,
            NOTIFICATIONS_PATH,
            NOTIFICATIONS_INTERFACE,
            "ActionInvoked",
            &(notification_id, "reopen"),
        )
        .await
        .unwrap();

    // Either outcome ends the wait, so a click that failed is reported as
    // *what it said* rather than as a test that ran out of patience.
    let failure_shown = || -> Option<Shown> {
        shown
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.summary.contains("Could not reopen"))
            .cloned()
    };
    until(
        "the reopen to be answered one way or the other",
        &bus,
        || {
            if let Some(failure) = failure_shown() {
                panic!(
                    "the click was answered with a failure on the user's screen: \
                 {} -- {}\nA recoverable, self-healing event was presented as \
                 something wrong.\n--- the helper's log ---\n{}",
                    failure.summary,
                    failure.body,
                    bus.log()
                );
            }
            agent.journal().contains("reopened 5173/tcp").then_some(())
        },
    )
    .await;
    // Before anything else is believed: the click really did land inside the
    // window, rather than after it on a name nobody owned -- which would have
    // been served first time and would have exercised no retry at all.
    was_held_by_the_leaving_instance("the reopen", clicked.elapsed(), &bus);

    // The port really is open again, read from a fresh instance rather than
    // taken from the agent's word for it.
    let rules = bus
        .proxy()
        .await
        .list()
        .await
        .expect("a helper answers `list`");
    assert_eq!(rules.len(), 1, "{rules:?}\n{}", bus.log());
    assert_eq!(rules[0].port, PORT);

    // And the two facts that make the assertion above mean something. First:
    // a retirement really was crossed -- the instance that refused is not the
    // instance that served, or nothing was ever retried.
    assert!(
        bus.activations() > activations_before,
        "one helper served the whole test, so the click never met a retiring \
         instance and this test measured nothing:\n{}",
        bus.log()
    );
    // Second: the failure this change exists to remove never appeared, at any
    // point, including after the reopen was reported done. The notification
    // list is the whole of what a person saw.
    assert!(
        failure_shown().is_none(),
        "a recoverable, self-healing event was put on the user's screen as a \
         failure: {:?}\n{}",
        failure_shown(),
        bus.log()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    not(debug_assertions),
    ignore = "`porthole-helper --session` and the retirement overrides are debug-only"
)]
async fn an_agent_that_starts_while_the_helper_is_retiring_still_wakes_one() {
    // The agent's other call, made at start-up and before it has announced
    // anything: `list`. Its *answer* is thrown away -- the call exists to
    // **start** the helper, after the subscription above it, so that whatever
    // the helper's own sweep announces reaches this agent instead of being
    // sent to nobody (see `main`'s own module doc on that ordering). A `list`
    // refused because the helper was leaving starts nothing, so an agent that
    // took the refusal for an answer would go on listening to a helper nobody
    // had woken -- and would say "could not reach the helper; listening
    // anyway" about one that was retiring exactly as designed.
    //
    // The version read that runs just before it is *not* refused, and that is
    // deliberate on the helper's side rather than an accident here:
    // `ProtocolVersion` is the one method outside `Retirement::admit` -- its
    // reply is `u` and nothing else, so there is no error a retiring helper
    // could put in it -- and this test pins that, because it is what decides
    // which of the agent's two start-up calls meets the window at all.
    let bus = Bus::start(700, PRERELEASE);

    // Activate a helper and then leave it alone, so its grace runs out.
    bus.proxy()
        .await
        .list()
        .await
        .expect("the first call activates a helper");
    until_it_has_decided_to_go(&bus).await;
    assert_eq!(bus.activations(), 1, "log:\n{}", bus.log());

    // The agent starts inside the window.
    let started = Instant::now();
    let agent = Agent::start(&bus);
    until("the agent to finish starting", &bus, || {
        agent.journal().contains("listening for uid").then_some(())
    })
    .await;
    was_held_by_the_leaving_instance("the agent's start-up", started.elapsed(), &bus);

    let journal = agent.journal();
    assert!(
        !journal.contains("could not reach the helper"),
        "the agent reported a helper it could not reach, about one that was \
         retiring exactly as designed:\n{journal}\n--- helper ---\n{}",
        bus.log()
    );
    // What the call was for: a helper is awake and subscribed to, which is
    // the fact the refusal would otherwise have cost. Instance one is
    // leaving, so this can only be a second.
    assert!(
        bus.activations() >= 2,
        "the agent's start-up call woke nothing, so it is listening to a \
         helper that does not exist:\n{}",
        bus.log()
    );
    // And the version really was answered by the instance that was leaving,
    // which is why it is not the call that needed asking twice.
    assert!(
        journal.contains("the helper speaks porthole's protocol"),
        "{journal}"
    );
}
