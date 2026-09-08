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

#[tokio::test]
async fn a_second_agent_in_one_session_stops_instead_of_doubling_every_notice() {
    // porthole ships both a systemd user unit and an XDG autostart entry --
    // desktops differ in which they honour, and one that honours both would
    // start two agents. The second must stop, and the first must be left
    // alone doing its job.
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

    let mut first = Agent::start(&bus);
    until("the first agent to start listening", || {
        first.journal().contains("listening for uid").then_some(())
    })
    .await;

    let mut second = Agent::start(&bus);
    let status = until("the second agent to exit", || {
        second.child.try_wait().expect("waitable")
    })
    .await;
    assert!(
        status.success(),
        "a second agent is an ordinary thing to be, not a failure: {status:?}"
    );
    assert!(
        second.journal().contains("already has an agent"),
        "it must say why it stopped: {}",
        second.journal()
    );

    // One close, one notification -- not two.
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
    assert!(first.is_running());
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
