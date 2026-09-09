//! The agent as a process, on a private session bus.
//!
//! Every test here starts `dbus-run-session`, points both
//! `DBUS_SESSION_BUS_ADDRESS` and `DBUS_SYSTEM_BUS_ADDRESS` at it, and runs
//! the real `porthole-agent` binary against stand-ins for the two services it
//! talks to. Nothing reaches this machine's own buses, and the agent has no
//! way to touch a firewall in any case: it opens no ports itself, it asks a
//! helper to, and the helper here is forty lines of test code that records
//! the request and answers it.
//!
//! What this proves is the wiring: a `RuleClosed` becomes a `Notify` with the
//! right words on it, one for another uid becomes nothing, an `ActionInvoked`
//! becomes an `Open` carrying the original request -- or a `Forward`, when
//! the rule was one, which the stand-in helper records separately so a test
//! can fail for the difference -- and a bus where nothing answers `Notify`
//! leaves the process running. What it does not prove is
//! anything about a real notification daemon -- the stand-in below answers
//! the method and emits the signal, it does not draw a bubble or wait for a
//! human to click it -- nor anything about the real helper or polkit.

use porthole_core::ipc::{CloseReason, WireRule, INTERFACE, PATH, SERVICE};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zbus::zvariant::OwnedValue;

/// The session name one agent per session holds, spelled here because an
/// integration test cannot reach into the binary's own `AGENT_SERVICE`.
/// `crates/porthole-agent/src/main.rs` is where the real one lives; a rename
/// there that is not made here turns the two tests below into tests of a name
/// nothing claims.
const AGENT_SERVICE: &str = "com.jacopobriccola.PortholeAgent";

const NOTIFICATIONS_SERVICE: &str = "org.freedesktop.Notifications";
const NOTIFICATIONS_PATH: &str = "/org/freedesktop/Notifications";
const NOTIFICATIONS_INTERFACE: &str = "org.freedesktop.Notifications";

/// How long any of these will wait for something to arrive over the bus
/// before calling it a failure. Generous on purpose: a slow machine under a
/// parallel `cargo test` is not the thing under test.
const DEADLINE: Duration = Duration::from_secs(15);

const OPENED_AT: u64 = 1_757_000_000;
const EXPIRES_AT: u64 = 1_757_003_600;
const OUR_UID: u32 = 4242;

/// A private bus, alive for as long as this value is.
///
/// The inner shell prints the address and then blocks reading its own stdin,
/// so dropping this closes that pipe, the shell exits, and `dbus-run-session`
/// takes the daemon down with it on its own -- no signals, no orphaned
/// `dbus-daemon` left behind for the next test to find.
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
    fn start(bus: &Bus) -> Agent {
        let stderr = tempfile::NamedTempFile::new().expect("a temp file for the agent's stderr");
        let child = Command::new(env!("CARGO_BIN_EXE_porthole-agent"))
            // Both buses are this one private bus. The agent asks for the
            // system bus by name and gets it here, which is the only reason
            // a test can stand in front of it at all.
            .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
            .env("DBUS_SYSTEM_BUS_ADDRESS", &bus.address)
            .env_remove("DBUS_STARTER_ADDRESS")
            .env_remove("DBUS_STARTER_BUS_TYPE")
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

fn wire_rule(port: u16, uid: u32) -> WireRule {
    WireRule {
        id: "abc".to_string(),
        port,
        protocol: "tcp".to_string(),
        target: "10.10.10.0/24".to_string(),
        scope: "network".to_string(),
        backend: "firewalld".to_string(),
        opened_at: OPENED_AT,
        expires_at: EXPIRES_AT,
        uid,
        // Not a forward: an empty address is what says so.
        container_addr: String::new(),
        container_port: 0,
        published_port: 0,
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
    /// Handed back as the notification id, and what the test then sends
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

/// A rule that redirects rather than permits, as `list` reports one. A
/// non-empty `container_addr` is the wire's own way of saying which of the
/// two acts created it -- see `WireRule`'s doc comment.
fn wire_forward(port: u16, published_port: u16, uid: u32) -> WireRule {
    WireRule {
        container_addr: "172.18.0.2".to_string(),
        container_port: 8080,
        published_port,
        ..wire_rule(port, uid)
    }
}

/// One `Open` call, as the stand-in helper received it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Opened {
    port: u16,
    protocol: String,
    scope: String,
    seconds: u32,
}

/// One `Forward` call. A separate record from [`Opened`], deliberately: a
/// test that could not tell the two methods apart could not fail for the
/// thing this file most needs it to fail for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Forwarded {
    port: u16,
    protocol: String,
    scope: String,
    seconds: u32,
    published_port: u16,
}

#[derive(Default)]
struct FakeHelper {
    opens: Arc<Mutex<Vec<Opened>>>,
    forwards: Arc<Mutex<Vec<Forwarded>>>,
}

#[zbus::interface(name = "com.jacopobriccola.Porthole1")]
impl FakeHelper {
    /// The agent calls this once at start-up, for the call itself rather
    /// than the answer.
    async fn list(&self) -> Vec<WireRule> {
        Vec::new()
    }

    async fn open(&self, port: u16, protocol: String, scope: String, seconds: u32) -> WireRule {
        self.opens.lock().expect("not poisoned").push(Opened {
            port,
            protocol: protocol.clone(),
            scope,
            seconds,
        });
        let mut rule = wire_rule(port, OUR_UID);
        rule.protocol = protocol;
        rule
    }

    async fn forward(
        &self,
        port: u16,
        protocol: String,
        scope: String,
        seconds: u32,
        published_port: u16,
    ) -> WireRule {
        self.forwards.lock().expect("not poisoned").push(Forwarded {
            port,
            protocol: protocol.clone(),
            scope,
            seconds,
            published_port,
        });
        let mut rule = wire_forward(port, published_port, OUR_UID);
        rule.protocol = protocol;
        rule
    }
}

/// Which connection currently holds [`AGENT_SERVICE`], as the bus reports it.
///
/// `None` while nobody holds it, which is an ordinary answer here: between
/// one agent releasing the name and the next taking it there is a moment when
/// it is unowned.
async fn agent_name_owner(dbus: &zbus::fdo::DBusProxy<'_>) -> Option<String> {
    dbus.get_name_owner(AGENT_SERVICE.try_into().expect("a well-formed bus name"))
        .await
        .ok()
        .map(|owner| owner.to_string())
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

/// The agent's own uid, which is the test process's uid: a signal has to
/// carry that uid for the agent to act on it, and any other for it not to.
fn our_uid() -> u32 {
    // SAFETY: getuid takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

#[tokio::test]
async fn a_close_notifies_its_own_user_only_and_a_reopen_re_sends_the_original_open() {
    let bus = Bus::start();
    let uid = our_uid();

    let shown = Arc::new(Mutex::new(Vec::new()));
    let opens = Arc::new(Mutex::new(Vec::new()));
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

    let helper = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(SERVICE)
        .unwrap()
        .serve_at(
            PATH,
            FakeHelper {
                opens: opens.clone(),
                ..Default::default()
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let mut agent = Agent::start(&bus);
    // Both services are up before the agent starts, so its own start-up
    // `list` is what tells us its subscription is in place: nothing is
    // emitted until that call has landed.
    until("the agent to call the helper", || {
        agent.journal().contains("listening for uid").then_some(())
    })
    .await;

    // A close belonging to somebody else, then one belonging to us. Both come
    // from the same sender, so the bus delivers them in this order: if the
    // foreign one produced a notification, it would be the first one shown.
    for rule in [wire_rule(6000, uid.wrapping_add(1)), wire_rule(5173, uid)] {
        helper
            .emit_signal(
                None::<()>,
                PATH,
                INTERFACE,
                "RuleClosed",
                &(rule, CloseReason::Expired),
            )
            .await
            .unwrap();
    }

    let first = until("a notification", || shown.lock().unwrap().first().cloned()).await;
    assert!(
        first.body.contains("5173/tcp"),
        "the notification shown was for somebody else's port: {first:?}"
    );
    assert!(first.body.contains("expired"), "{first:?}");
    assert!(first.summary.contains("5173/tcp"), "{first:?}");
    assert_eq!(
        first.actions,
        vec!["reopen".to_string(), "Reopen".to_string()],
        "an expiry offers exactly one action, as a key/label pair"
    );

    // The click.
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

    let opened = until("the reopen to reach the helper", || {
        opens.lock().unwrap().first().cloned()
    })
    .await;
    assert_eq!(
        opened,
        Opened {
            port: 5173,
            protocol: "tcp".to_string(),
            // The rule's own CIDR, not the word `subnet`: reopening asks for
            // the network the rule was actually towards.
            scope: "10.10.10.0/24".to_string(),
            // The length it was open for, not the instant it would have
            // ended -- that instant is in the past by now.
            seconds: (EXPIRES_AT - OPENED_AT) as u32,
        }
    );

    assert_eq!(
        shown.lock().unwrap().len(),
        1,
        "the foreign uid's close must still have produced nothing"
    );
    assert!(agent.is_running());
}

#[tokio::test]
async fn a_gone_container_offers_reopen_and_the_click_sends_a_forward_not_an_open() {
    // Two things at once, and both matter.
    //
    // `TargetGone` offers `Reopen` where a network change does not, because
    // a forward's request names a published port and the helper resolves the
    // container from Docker's own table each time it acts -- so a container
    // that restarted somewhere else is found again rather than lost. That is
    // the *only* reason the button can be honest here.
    //
    // And the click has to send `forward`. Sending `open` for a forward's
    // external port would permit the local network to a port on this machine
    // that nothing answers on: the redirect was the whole of what that port
    // meant. Recording the two methods separately in the stand-in helper is
    // what lets this fail for that, rather than merely observing that
    // *something* reached the helper.
    let bus = Bus::start();
    let uid = our_uid();

    let shown = Arc::new(Mutex::new(Vec::new()));
    let opens = Arc::new(Mutex::new(Vec::new()));
    let forwards = Arc::new(Mutex::new(Vec::new()));
    let notification_id = 11;

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

    let helper = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(SERVICE)
        .unwrap()
        .serve_at(
            PATH,
            FakeHelper {
                opens: opens.clone(),
                forwards: forwards.clone(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let mut agent = Agent::start(&bus);
    until("the agent to start listening", || {
        agent.journal().contains("listening for uid").then_some(())
    })
    .await;

    helper
        .emit_signal(
            None::<()>,
            PATH,
            INTERFACE,
            "RuleClosed",
            &(wire_forward(8443, 3000, uid), CloseReason::TargetGone),
        )
        .await
        .unwrap();

    let notice = until("a notification", || shown.lock().unwrap().first().cloned()).await;
    assert!(notice.body.contains("8443/tcp"), "{notice:?}");
    assert_eq!(
        notice.actions,
        vec!["reopen".to_string(), "Reopen".to_string()],
        "a container that moved can be found again, so this one offers the button"
    );

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

    let sent = until("the reopen to reach the helper", || {
        forwards.lock().unwrap().first().cloned()
    })
    .await;
    assert_eq!(
        sent,
        Forwarded {
            port: 8443,
            protocol: "tcp".to_string(),
            scope: "10.10.10.0/24".to_string(),
            seconds: (EXPIRES_AT - OPENED_AT) as u32,
            // The published port, never the container address the closed
            // rule happened to hold: the helper resolves that afresh, which
            // is the whole point of closing rather than re-aiming.
            published_port: 3000,
        }
    );
    assert!(
        opens.lock().unwrap().is_empty(),
        "the click opened the external port instead of re-creating the redirect: {:?}",
        opens.lock().unwrap()
    );
    assert!(agent.is_running());
}

#[tokio::test]
async fn a_reopen_of_an_expired_forward_sends_a_forward_not_an_open() {
    // The bug this whole branch's agent change was written for, named at
    // last. A forward is an ordinary rule with an expiry, and `Expired` has
    // offered `Reopen` since this binary existed -- so long before
    // `TargetGone` was reachable, a click here already sent `open` for the
    // forward's external port: permitting the local network to a port on
    // this machine that nothing answers on, because the redirect was the
    // whole of what that port meant.
    //
    // `TargetGone`'s own session test above cannot stand in for this one.
    // That reason is only ever emitted for forwards, so a `reopen_request`
    // that keyed off the *reason* rather than the rule would pass it and
    // still be wrong here. This case is what tells the two apart.
    let bus = Bus::start();
    let uid = our_uid();

    let shown = Arc::new(Mutex::new(Vec::new()));
    let opens = Arc::new(Mutex::new(Vec::new()));
    let forwards = Arc::new(Mutex::new(Vec::new()));
    let notification_id = 17;

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

    let helper = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(SERVICE)
        .unwrap()
        .serve_at(
            PATH,
            FakeHelper {
                opens: opens.clone(),
                forwards: forwards.clone(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let mut agent = Agent::start(&bus);
    until("the agent to start listening", || {
        agent.journal().contains("listening for uid").then_some(())
    })
    .await;

    helper
        .emit_signal(
            None::<()>,
            PATH,
            INTERFACE,
            "RuleClosed",
            &(wire_forward(8443, 3000, uid), CloseReason::Expired),
        )
        .await
        .unwrap();

    let notice = until("a notification", || shown.lock().unwrap().first().cloned()).await;
    assert!(notice.body.contains("8443/tcp"), "{notice:?}");
    // The words beside the button, not only the button: a person pressing
    // it has to know they are restoring a redirect.
    assert!(
        notice.body.contains("redirect") && notice.body.contains("3000"),
        "an expired forward's notification must say what it was: {notice:?}"
    );
    assert_eq!(
        notice.actions,
        vec!["reopen".to_string(), "Reopen".to_string()],
        "an expiry has always offered the button, and still does"
    );

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

    let sent = until("the reopen to reach the helper", || {
        forwards.lock().unwrap().first().cloned()
    })
    .await;
    assert_eq!(
        sent,
        Forwarded {
            port: 8443,
            protocol: "tcp".to_string(),
            scope: "10.10.10.0/24".to_string(),
            seconds: (EXPIRES_AT - OPENED_AT) as u32,
            published_port: 3000,
        }
    );
    assert!(
        opens.lock().unwrap().is_empty(),
        "the click opened the external port instead of re-creating the redirect: {:?}",
        opens.lock().unwrap()
    );
    assert!(agent.is_running());
}

#[tokio::test]
async fn a_network_change_is_announced_without_a_button_that_could_not_work() {
    // The other half of the pair above, kept as its own check so that making
    // the two reasons "consistent" cannot pass silently. A rule scoped to a
    // subnet this machine has left names that subnet in its own request, and
    // nothing re-resolves it: a `Reopen` would build a rule that appears to
    // work and reaches nobody. The notification still happens -- the user
    // has to be told the port closed -- it simply offers nothing.
    let bus = Bus::start();
    let uid = our_uid();

    let shown = Arc::new(Mutex::new(Vec::new()));
    let opens = Arc::new(Mutex::new(Vec::new()));
    let forwards = Arc::new(Mutex::new(Vec::new()));

    let _notifications = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(NOTIFICATIONS_SERVICE)
        .unwrap()
        .serve_at(
            NOTIFICATIONS_PATH,
            FakeNotifications {
                shown: shown.clone(),
                id: 13,
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let helper = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(SERVICE)
        .unwrap()
        .serve_at(
            PATH,
            FakeHelper {
                opens: opens.clone(),
                forwards: forwards.clone(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let mut agent = Agent::start(&bus);
    until("the agent to start listening", || {
        agent.journal().contains("listening for uid").then_some(())
    })
    .await;

    helper
        .emit_signal(
            None::<()>,
            PATH,
            INTERFACE,
            "RuleClosed",
            &(wire_rule(5173, uid), CloseReason::NetworkChanged),
        )
        .await
        .unwrap();

    let notice = until("a notification", || shown.lock().unwrap().first().cloned()).await;
    assert!(notice.body.contains("5173/tcp"), "{notice:?}");
    assert!(
        notice.actions.is_empty(),
        "a rule for a subnet this machine has left must offer no button: {notice:?}"
    );
    assert!(agent.is_running());
}

#[tokio::test]
async fn a_missing_notification_service_does_not_kill_the_agent() {
    // A headless login or a session without a notification daemon must not
    // leave a crash-looping user unit behind. Nothing owns
    // `org.freedesktop.Notifications` on this bus, so every `Notify` comes
    // back as an error, and the agent has to keep listening through it.
    let bus = Bus::start();
    let uid = our_uid();
    let opens = Arc::new(Mutex::new(Vec::new()));

    let helper = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(SERVICE)
        .unwrap()
        .serve_at(
            PATH,
            FakeHelper {
                opens: opens.clone(),
                ..Default::default()
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let mut agent = Agent::start(&bus);
    until("the agent to start listening", || {
        agent.journal().contains("listening for uid").then_some(())
    })
    .await;

    for port in [5173, 8080] {
        helper
            .emit_signal(
                None::<()>,
                PATH,
                INTERFACE,
                "RuleClosed",
                &(wire_rule(port, uid), CloseReason::Expired),
            )
            .await
            .unwrap();
    }

    // Twice: a single survived failure could be one the agent never reached.
    // The second line proves it was still reading the bus afterwards.
    until("both failures to be recorded", || {
        let journal = agent.journal();
        (journal.matches("could not be shown").count() == 2).then_some(())
    })
    .await;
    let journal = agent.journal();
    assert!(journal.contains("5173/tcp"), "{journal}");
    assert!(journal.contains("8080/tcp"), "{journal}");
    assert!(
        agent.is_running(),
        "the agent exited instead of carrying on: {journal}"
    );

    // And it is still the same process a moment later, not one on its way
    // out with an exit status not yet collected.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(agent.is_running(), "{}", agent.journal());
}

/// Two agents in one session leave exactly one, and it is the newer one.
///
/// porthole ships both a systemd user unit and an XDG autostart entry --
/// desktops differ in which they honour, and one that honours both starts
/// two agents. One of them has to stop.
///
/// **Which one changed, and why.** It used to be the second: the name went
/// to whoever got there first and a later agent found it taken and exited.
/// After an upgrade that meant the *stale* agent kept the name -- the user
/// bus outlives a login session -- so every newly started agent exited,
/// `systemctl --user restart` could not help (the stale process is not the
/// unit's), and the user got no notifications at all with nothing but a
/// journal line to say so. So the newer agent takes the name now.
///
/// What has not changed is what this test is really for: one close, one
/// notification. Two live agents would announce every close twice, and that
/// is the thing the name exists to prevent.
#[tokio::test]
async fn a_newer_agent_takes_the_name_and_the_older_one_stops() {
    let bus = Bus::start();
    let uid = our_uid();

    let shown = Arc::new(Mutex::new(Vec::new()));
    let opens = Arc::new(Mutex::new(Vec::new()));

    let _notifications = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(NOTIFICATIONS_SERVICE)
        .unwrap()
        .serve_at(
            NOTIFICATIONS_PATH,
            FakeNotifications {
                shown: shown.clone(),
                id: 7,
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let helper = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(SERVICE)
        .unwrap()
        .serve_at(
            PATH,
            FakeHelper {
                opens: opens.clone(),
                ..Default::default()
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    // The bus's own view of who owns the name, which is the fact this test
    // is about. Read from a third connection rather than inferred from
    // either agent's journal: a flag passed to `RequestName` proves nothing
    // about who ended up with the name.
    let watcher = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let dbus = zbus::fdo::DBusProxy::new(&watcher).await.unwrap();

    let mut first = Agent::start(&bus);
    until("the first agent to start listening", || {
        first.journal().contains("listening for uid").then_some(())
    })
    .await;
    let first_owner = agent_name_owner(&dbus)
        .await
        .expect("the first agent owns the name once it is listening");

    let mut second = Agent::start(&bus);

    // The name changed hands. Not "the second is running" and not "the first
    // said something": the unique connection behind AGENT_SERVICE is a
    // different one than it was.
    let deadline = std::time::Instant::now() + DEADLINE;
    let second_owner = loop {
        match agent_name_owner(&dbus).await {
            Some(owner) if owner != first_owner => break owner,
            _ => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "timed out: the name never changed hands (still {first_owner}). \
                     first: {} second: {}",
                    first.journal(),
                    second.journal()
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };
    assert_ne!(first_owner, second_owner);

    let status = until("the older agent to exit", || {
        first.child.try_wait().expect("waitable")
    })
    .await;
    assert!(
        status.success(),
        "being replaced is an ordinary thing to happen, not a failure: {status:?}"
    );
    assert!(
        first.journal().contains("a newer agent took"),
        "it must say why it stopped: {}",
        first.journal()
    );
    assert!(
        second.is_running(),
        "the agent that took the name must be the one left: {}",
        second.journal()
    );

    // One close, one notification -- not two. The point of the name.
    helper
        .emit_signal(
            None::<()>,
            PATH,
            INTERFACE,
            "RuleClosed",
            &(wire_rule(5173, uid), CloseReason::Expired),
        )
        .await
        .unwrap();
    until("a notification", || shown.lock().unwrap().first().cloned()).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(shown.lock().unwrap().len(), 1);
    assert!(second.is_running());
}

/// The one case replacement cannot fix, and the one this defect was
/// reported from: a holder that will not give the name up.
///
/// `ReplaceExisting` only takes a name from an owner that asked for
/// `AllowReplacement`. Every agent of this version does; an agent from
/// before this change did not -- so the first upgrade past it still meets a
/// stale agent that keeps the name. What must not happen again is that the
/// user finds out from the journal or not at all.
///
/// The squatter here is this test's own connection, holding the name without
/// offering replacement: exactly the pre-upgrade agent's request, made by
/// forty lines of test code instead of an old binary.
#[tokio::test]
async fn an_agent_that_cannot_take_the_name_says_so_on_screen_not_only_in_the_journal() {
    let bus = Bus::start();

    let shown = Arc::new(Mutex::new(Vec::new()));
    let _notifications = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(NOTIFICATIONS_SERVICE)
        .unwrap()
        .serve_at(
            NOTIFICATIONS_PATH,
            FakeNotifications {
                shown: shown.clone(),
                id: 11,
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let squatter = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let reply = squatter
        .request_name_with_flags(
            AGENT_SERVICE,
            zbus::fdo::RequestNameFlags::DoNotQueue.into(),
        )
        .await
        .expect("the name is free");
    assert_eq!(
        reply,
        zbus::fdo::RequestNameReply::PrimaryOwner,
        "the squatter has to actually hold the name for this test to mean anything"
    );

    let mut agent = Agent::start(&bus);
    let status = until("the agent to give up", || {
        agent.child.try_wait().expect("waitable")
    })
    .await;
    assert!(
        status.success(),
        "giving up is not a failure a service manager should restart: {status:?}"
    );

    let notice = until("the notice", || shown.lock().unwrap().first().cloned()).await;
    assert!(
        notice.summary.to_lowercase().contains("porthole"),
        "a notification with no porthole in it says nothing about porthole: {notice:?}"
    );
    assert!(
        notice.body.contains("older") && notice.body.contains("upgrade"),
        "the notice has to name the likely cause, or it is not actionable: {notice:?}"
    );
    assert!(
        notice.actions.is_empty(),
        "no button: the agent is gone by the time anyone could click one: {notice:?}"
    );
    assert!(
        !agent.journal().is_empty(),
        "the journal line stays too -- the notice is in addition to it, not instead"
    );
}

#[tokio::test]
async fn a_click_after_the_notification_service_restarted_never_reopens_a_stale_port() {
    // A notification id means something only within one run of one
    // notification server. Restart the server and it numbers from the start
    // again, so an id the agent is still holding can name a notification
    // nobody can see any more -- and a click carrying that id would reopen
    // the port that notification was about, while the user is looking at a
    // different one and believes that is what they authorized.
    let bus = Bus::start();
    let uid = our_uid();
    let opens = Arc::new(Mutex::new(Vec::new()));
    let before = Arc::new(Mutex::new(Vec::new()));
    let after = Arc::new(Mutex::new(Vec::new()));
    // The same id from both runs, which is the whole point: a server that
    // numbered differently after a restart would hide this by accident.
    let reused_id = 7;

    let helper = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(SERVICE)
        .unwrap()
        .serve_at(
            PATH,
            FakeHelper {
                opens: opens.clone(),
                ..Default::default()
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let first_run = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(NOTIFICATIONS_SERVICE)
        .unwrap()
        .serve_at(
            NOTIFICATIONS_PATH,
            FakeNotifications {
                shown: before.clone(),
                id: reused_id,
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let mut agent = Agent::start(&bus);
    until("the agent to start listening", || {
        agent.journal().contains("listening for uid").then_some(())
    })
    .await;

    // One notification under the first run: the agent is now holding id 7
    // against port 5173.
    helper
        .emit_signal(
            None::<()>,
            PATH,
            INTERFACE,
            "RuleClosed",
            &(wire_rule(5173, uid), CloseReason::Expired),
        )
        .await
        .unwrap();
    until("the first notification", || {
        before.lock().unwrap().first().cloned()
    })
    .await;

    // The restart. Waiting for the agent to say it forgot is also what makes
    // the rest of this deterministic: the line cannot appear before the bus
    // has broadcast the name's release, so the name is free to take again.
    drop(first_run);
    until("the agent to forget the first run's ids", || {
        agent
            .journal()
            .contains("forgetting 1 notification id(s)")
            .then_some(())
    })
    .await;

    let second_run = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(NOTIFICATIONS_SERVICE)
        .unwrap()
        .serve_at(
            NOTIFICATIONS_PATH,
            FakeNotifications {
                shown: after.clone(),
                id: reused_id,
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    // A click carrying the reused id, with nothing yet shown under the new
    // run. Nothing may be reopened: the only rule that id ever named belongs
    // to a notification that no longer exists.
    second_run
        .emit_signal(
            None::<()>,
            NOTIFICATIONS_PATH,
            NOTIFICATIONS_INTERFACE,
            "ActionInvoked",
            &(reused_id, "reopen"),
        )
        .await
        .unwrap();
    until("the agent to refuse the stale click", || {
        agent.journal().contains("no longer holds").then_some(())
    })
    .await;
    assert!(
        opens.lock().unwrap().is_empty(),
        "a click on a notification from before the restart reopened something: {:?}",
        opens.lock().unwrap()
    );

    // Now a real notification under the new run, taking the same id back.
    helper
        .emit_signal(
            None::<()>,
            PATH,
            INTERFACE,
            "RuleClosed",
            &(wire_rule(8080, uid), CloseReason::Expired),
        )
        .await
        .unwrap();
    let shown = until("the second run's notification", || {
        after.lock().unwrap().first().cloned()
    })
    .await;
    assert!(shown.body.contains("8080/tcp"), "{shown:?}");

    second_run
        .emit_signal(
            None::<()>,
            NOTIFICATIONS_PATH,
            NOTIFICATIONS_INTERFACE,
            "ActionInvoked",
            &(reused_id, "reopen"),
        )
        .await
        .unwrap();
    let opened = until("the reopen to reach the helper", || {
        opens.lock().unwrap().first().cloned()
    })
    .await;
    assert_eq!(
        opened.port, 8080,
        "the click reopened the port from before the restart, not the one on the screen"
    );
    assert!(agent.is_running());
}

/// [`WireRule`] as it was before the forward feature -- nine members, not
/// twelve.
///
/// This is the whole of what an agent from before that upgrade is built
/// against, and serving it from a stand-in helper is how these tests put a
/// real signature mismatch on a real bus. Spelled out rather than derived
/// from `WireRule` on purpose: a shape derived from the type under test
/// would follow it forward and stop being the old one.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zbus::zvariant::Type)]
struct RuleBeforeForward {
    id: String,
    port: u16,
    protocol: String,
    target: String,
    scope: String,
    backend: String,
    opened_at: u64,
    expires_at: u64,
    uid: u32,
}

fn rule_before_forward(port: u16, uid: u32) -> RuleBeforeForward {
    RuleBeforeForward {
        id: "abc".to_string(),
        port,
        protocol: "tcp".to_string(),
        target: "10.10.10.0/24".to_string(),
        scope: "network".to_string(),
        backend: "firewalld".to_string(),
        opened_at: OPENED_AT,
        expires_at: EXPIRES_AT,
        uid,
    }
}

/// A helper whose `list` answers in the shape from before the forward
/// feature: `a(sqssssttu)` where this agent expects `a(sqssssttusqq)`.
///
/// The agent calls `list` once at start-up for the call's own sake, and it
/// is that call's *return* signature that the upgrade changed -- so this is
/// the very first thing a mismatched pair says to each other, and it used to
/// be answered with `listening anyway`.
struct HelperFromBeforeForward;

#[zbus::interface(name = "com.jacopobriccola.Porthole1")]
impl HelperFromBeforeForward {
    async fn list(&self) -> Vec<RuleBeforeForward> {
        vec![rule_before_forward(5173, OUR_UID)]
    }
}

/// A close the agent cannot read stops it, on screen.
///
/// The defect measured on 2026-09-09 and reported by the owner: after an
/// upgrade, an agent from before it went on running and announced **nothing
/// at all, for any close**, in silence. zbus was not what dropped those
/// signals -- it delivers them and keeps the stream alive; the agent's own
/// loop discarded the `args()` error and went round again.
///
/// Everything here is real: the mismatch is a body of the previous shape put
/// on a real bus by a real `emit_signal`, and what is asserted is what a
/// person would see -- a notification, and a process that stopped.
#[tokio::test]
async fn a_close_this_agent_cannot_read_stops_it_and_says_so_on_screen() {
    let bus = Bus::start();
    let uid = our_uid();

    let shown = Arc::new(Mutex::new(Vec::new()));
    let _notifications = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(NOTIFICATIONS_SERVICE)
        .unwrap()
        .serve_at(
            NOTIFICATIONS_PATH,
            FakeNotifications {
                shown: shown.clone(),
                id: 7,
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    // A helper that answers `list` in the *current* shape, so start-up gets
    // past it and this test is about the signal and nothing else.
    let helper = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(SERVICE)
        .unwrap()
        .serve_at(PATH, FakeHelper::default())
        .unwrap()
        .build()
        .await
        .unwrap();

    let mut agent = Agent::start(&bus);
    until("the agent to start listening", || {
        agent.journal().contains("listening for uid").then_some(())
    })
    .await;

    // The positive control, first and in this same process: a close of the
    // current shape is announced. Without it, a later "the agent stopped"
    // could be an agent that never worked.
    helper
        .emit_signal(
            None::<()>,
            PATH,
            INTERFACE,
            "RuleClosed",
            &(wire_rule(5173, uid), CloseReason::Expired),
        )
        .await
        .unwrap();
    let announced = until("the ordinary close to be announced", || {
        shown.lock().unwrap().first().cloned()
    })
    .await;
    assert!(announced.body.contains("5173/tcp"), "{announced:?}");
    assert!(agent.is_running(), "{}", agent.journal());

    // And now the same signal in the shape from before the upgrade.
    helper
        .emit_signal(
            None::<()>,
            PATH,
            INTERFACE,
            "RuleClosed",
            &(rule_before_forward(8080, uid), CloseReason::Expired),
        )
        .await
        .unwrap();

    let notice = until("the notice about a message it could not read", || {
        shown.lock().unwrap().get(1).cloned()
    })
    .await;
    assert!(
        notice.summary.to_lowercase().contains("porthole"),
        "a notification with no porthole in it says nothing about porthole: {notice:?}"
    );
    assert!(
        notice.body.contains("could not read"),
        "the notice has to say what happened, not merely that something did: {notice:?}"
    );
    assert!(
        notice.body.contains("porthole-helper.service")
            && notice.body.to_lowercase().contains("log out"),
        "and both remedies, since nothing here knows which half is old: {notice:?}"
    );

    let status = until("the agent to stop", || {
        agent.child.try_wait().expect("waitable")
    })
    .await;
    assert!(
        status.success(),
        "stopping here is not a failure to restart into: a fresh agent meets the same \
         helper and fails the same way: {status:?}"
    );

    let journal = agent.journal();
    assert!(
        journal.contains("could not read a RuleClosed"),
        "the journal keeps the whole error, which is where the two signatures are: {journal}"
    );
    assert!(
        journal.contains("ignature"),
        "and zbus's own text names them: {journal}"
    );
}

/// The same fact arriving earlier: the start-up `list` this agent makes for
/// the call's own sake carries `WireRule` in its answer.
///
/// This is the loud failure that already existed and was already ignored --
/// `could not reach the helper (Signature mismatch: ...); listening anyway`,
/// written to a journal by an agent that then went on to announce nothing
/// for the rest of the login. "Listening anyway" is a true sentence about a
/// helper that is not installed and a false promise about one whose language
/// this binary does not speak.
#[tokio::test]
async fn a_list_this_agent_cannot_read_stops_it_instead_of_listening_anyway() {
    let bus = Bus::start();

    let shown = Arc::new(Mutex::new(Vec::new()));
    let _notifications = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(NOTIFICATIONS_SERVICE)
        .unwrap()
        .serve_at(
            NOTIFICATIONS_PATH,
            FakeNotifications {
                shown: shown.clone(),
                id: 3,
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let _helper = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(SERVICE)
        .unwrap()
        .serve_at(PATH, HelperFromBeforeForward)
        .unwrap()
        .build()
        .await
        .unwrap();

    let mut agent = Agent::start(&bus);
    let status = until("the agent to stop", || {
        agent.child.try_wait().expect("waitable")
    })
    .await;
    assert!(status.success(), "{status:?}");

    let notice = until("the notice", || shown.lock().unwrap().first().cloned()).await;
    assert!(notice.body.contains("could not read"), "{notice:?}");

    let journal = agent.journal();
    assert!(
        !journal.contains("listening anyway"),
        "this is not the recoverable case, and must not be described as it: {journal}"
    );
    assert!(
        !journal.contains("listening for uid"),
        "an agent that cannot read the helper is not listening to anything: {journal}"
    );
}

/// And the other half of that distinction, which is the whole reason the
/// first one is allowed to stop: a helper that is simply **absent** is
/// ordinary and recoverable, and nothing here may treat it as a version
/// mismatch.
///
/// Nothing owns `com.jacopobriccola.Porthole` on this bus and nothing can be
/// activated to, which is exactly a machine where the helper is not
/// installed yet, or not installed at all. The agent keeps listening, and
/// puts nothing on the screen: there is nothing wrong to report.
#[tokio::test]
async fn an_absent_helper_leaves_the_agent_listening_and_shows_nothing() {
    let bus = Bus::start();

    let shown = Arc::new(Mutex::new(Vec::new()));
    let _notifications = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(NOTIFICATIONS_SERVICE)
        .unwrap()
        .serve_at(
            NOTIFICATIONS_PATH,
            FakeNotifications {
                shown: shown.clone(),
                id: 5,
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let mut agent = Agent::start(&bus);
    until("the agent to start listening", || {
        agent.journal().contains("listening for uid").then_some(())
    })
    .await;

    let journal = agent.journal();
    assert!(
        journal.contains("listening anyway"),
        "the absent helper still has to be reported as the ordinary thing it is: {journal}"
    );
    // Long enough that an agent on its way out would have gone.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        agent.is_running(),
        "an absent helper is recoverable -- the agent waits for it: {}",
        agent.journal()
    );
    assert!(
        shown.lock().unwrap().is_empty(),
        "and nothing is put on the user's screen about it: {:?}",
        shown.lock().unwrap()
    );
}
