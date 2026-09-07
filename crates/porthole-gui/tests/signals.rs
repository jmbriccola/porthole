//! What the window does about a rule it did not touch itself.
//!
//! Everything else in this crate drives the window through its own setters,
//! or through a button press. This file drives it through the bus: a
//! stand-in helper owns `com.jacopobriccola.Porthole`, answers `list`,
//! `status` and `docker_ports`, and puts a real `RuleOpened`/`RuleClosed`
//! on the wire. What is asserted is what a person looking at the window
//! would see afterwards -- a row gone, a "Listening" row's Open button
//! back -- not that a subscription exists.
//!
//! ## The bus these tests use
//!
//! `gui-test.sh` runs the whole target under `dbus-run-session`, which
//! provides a private *session* bus and nothing else; the container has no
//! system bus (see `tests/window.rs`'s own unreachable-helper check, which
//! depends on that). `main` below points `DBUS_SYSTEM_BUS_ADDRESS` at that
//! same private daemon before any window is built, so the window's own
//! `zbus::Connection::system()` reaches the stand-in here. Each `[[test]]`
//! target is its own process, so this is set for this file alone and the
//! other targets still fail against nothing, exactly as they did.
//!
//! Nothing here touches this machine's real buses, and the stand-in opens
//! no ports: it hands back rows a test put in it.
//!
//! ## The listener these tests scan
//!
//! The "Listening" section is filled from `/proc`, by the window's own
//! refresh, and there is no seam to feed it a fixture that the *next*
//! refresh would not overwrite. So these tests bind a real `TcpListener` on
//! `0.0.0.0`, on whatever port the kernel hands out, and let the real scan
//! find it -- a row that survives every refresh, because the socket is
//! genuinely there for as long as the test holds it.

use std::cell::{Cell, RefCell};
use std::net::TcpListener;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use adw::prelude::*;
use porthole_core::ipc::{
    CloseReason, WireDockerPort, WireRule, WireStatus, INTERFACE, PATH, SERVICE,
};
use porthole_gui::window::PortholeWindow;

/// How long any of these will wait for something to cross the bus and reach
/// a widget. Generous on purpose: a software-rendered GTK window in a
/// container under a cold cargo build is not the thing under test.
const DEADLINE: Duration = Duration::from_secs(20);

const OPENED_AT: u64 = 1_757_100_000;
const EXPIRES_AT: u64 = 1_757_103_600;

/// Runs `f` inside a real `adw::Application` activation -- the same helper
/// `tests/window.rs` and `tests/open_now.rs` each carry, for the same
/// reason: the widgets have to be built inside a real activation.
fn activate<F: FnOnce(&adw::Application) + 'static>(app_id: &str, f: F) {
    let app = adw::Application::builder().application_id(app_id).build();
    let f = Rc::new(RefCell::new(Some(f)));
    app.connect_activate(move |app| {
        if let Some(f) = f.borrow_mut().take() {
            f(app);
        }
        app.quit();
    });
    app.run_with_args::<&str>(&[]);
}

/// Drains the main context until `condition` holds, or `timeout` elapses --
/// the same bounded shape `tests/window.rs` uses, so a path that never
/// settles fails the test rather than hanging the process.
fn pump_until(condition: impl Fn() -> bool, timeout: Duration) -> bool {
    let context = gtk::glib::MainContext::default();
    let deadline = Instant::now() + timeout;
    loop {
        while context.iteration(false) {}
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return condition();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The rules the stand-in helper currently reports, shared with the test
/// that changes them.
type Rules = Arc<Mutex<Vec<WireRule>>>;

/// A helper that answers the three reads the window makes and does nothing
/// else. It never opens or closes anything: a test sets what `list` returns
/// and then announces the change itself, which is exactly the situation
/// this file exists to cover -- something outside this window changed what
/// is open.
struct StandInHelper {
    rules: Rules,
}

#[zbus::interface(name = "com.jacopobriccola.Porthole1")]
impl StandInHelper {
    async fn list(&self) -> Vec<WireRule> {
        self.rules.lock().expect("not poisoned").clone()
    }

    async fn status(&self) -> WireStatus {
        WireStatus {
            backend: "firewalld".to_string(),
            firewall_available: true,
            firewall_active: true,
            firewall_active_unknown: false,
            firewall_version: "2.3.0".to_string(),
            detail: "firewalld is running".to_string(),
            location: "FedoraWorkstation".to_string(),
            interface: "wlp2s0".to_string(),
            address: "10.10.10.20".to_string(),
            cidr: "10.10.10.0/24".to_string(),
            rules: self.rules.lock().expect("not poisoned").clone(),
        }
    }

    async fn docker_ports(&self) -> Vec<WireDockerPort> {
        Vec::new()
    }
}

fn wire_rule(port: u16) -> WireRule {
    WireRule {
        id: format!("{port}/tcp"),
        port,
        protocol: "tcp".to_string(),
        target: "10.10.10.0/24".to_string(),
        scope: "network".to_string(),
        backend: "firewalld".to_string(),
        opened_at: OPENED_AT,
        expires_at: EXPIRES_AT,
        uid: 1000,
    }
}

/// Which "Listening" row is the socket this test bound, by the port in its
/// own title (`"<process> · <port>"`, or the bare port when the owning
/// process could not be identified). The port comes from the kernel, so no
/// other row in the container can share it.
fn listening_row_for(win: &PortholeWindow, port: u16) -> Option<usize> {
    let suffix = format!("· {port}");
    let bare = port.to_string();
    win.listening().rows().iter().position(|row| {
        let title = row.title().to_string();
        title == bare || title.ends_with(&suffix)
    })
}

/// A rule that stops being open with nothing in this window asking must
/// leave it -- and give the "Listening" row its Open button back.
///
/// This is the defect a person found on a Fedora Workstation VM: a rule
/// opened for a minute, the firewall's own `--list-rich-rules` showing it
/// gone at expiry, and the window still showing the row. The row was
/// predicting the close from its own countdown and never learning whether
/// it happened.
///
/// Every step here is real: the row is built from the stand-in's `list`,
/// the "Listening" row from a real `/proc` scan of a socket this test
/// really bound, and the close arrives as a real `RuleClosed` on the bus.
fn a_rule_closed_elsewhere_leaves_the_window_and_frees_its_listening_row(
    connection: &zbus::blocking::Connection,
    rules: &Rules,
) -> Result<(), String> {
    let listener = TcpListener::bind(("0.0.0.0", 0)).map_err(|e| format!("no listener: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("no local address: {e}"))?
        .port();
    *rules.lock().expect("not poisoned") = vec![wire_rule(port)];

    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    let connection = connection.clone();
    let rules = rules.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.RuleClosedSignal",
        move |app| {
            let win = PortholeWindow::new(app);
            win.present();

            // Both reads have landed once "Open now" has the rule and the
            // scan has found this test's own socket.
            let loaded = pump_until(
                || win.open_now().rows().len() == 1 && listening_row_for(&win, port).is_some(),
                DEADLINE,
            );
            if !loaded {
                seen.replace(Some((false, false, false, false)));
                return;
            }
            let index = listening_row_for(&win, port).expect("just checked");
            let withheld = win.listening().open_button_for(index).is_none();

            // The helper closes it, and says so. Nothing in this window
            // asked for that, and nothing in this window is told directly.
            rules.lock().expect("not poisoned").clear();
            connection
                .emit_signal(
                    None::<()>,
                    PATH,
                    INTERFACE,
                    "RuleClosed",
                    &(wire_rule(port), CloseReason::Expired),
                )
                .expect("the stand-in can emit");

            let gone = pump_until(|| win.open_now().rows().is_empty(), DEADLINE);
            let back = listening_row_for(&win, port)
                .and_then(|index| win.listening().open_button_for(index))
                .is_some();
            seen.replace(Some((true, withheld, gone, back)));
            // So the next case's window is the only one listening.
            win.close();
        },
    );

    let (loaded, withheld, gone, back) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    drop(listener);
    if !loaded {
        return Err(
            "the window never showed the stand-in helper's rule alongside a Listening row for \
             the socket this test bound"
                .to_string(),
        );
    }
    if !withheld {
        return Err(
            "a port the helper reports open must leave its Listening row without an Open \
             button, or this check cannot tell the button coming back from its never having \
             gone"
                .to_string(),
        );
    }
    if !gone {
        return Err(
            "the helper announced the close and the window went on showing the rule as open"
                .to_string(),
        );
    }
    if !back {
        return Err(
            "the rule is gone from \"Open now\" but its Listening row still has no way to open \
             the port again"
                .to_string(),
        );
    }
    Ok(())
}

/// The other direction, and the same principle: a rule opened by something
/// else -- the CLI, another window, a notification's Reopen -- appears here
/// without anybody pressing anything in this window.
fn a_rule_opened_elsewhere_appears_without_the_window_asking(
    connection: &zbus::blocking::Connection,
    rules: &Rules,
) -> Result<(), String> {
    let listener = TcpListener::bind(("0.0.0.0", 0)).map_err(|e| format!("no listener: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("no local address: {e}"))?
        .port();
    rules.lock().expect("not poisoned").clear();

    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    let connection = connection.clone();
    let rules = rules.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.RuleOpenedSignal",
        move |app| {
            let win = PortholeWindow::new(app);
            win.present();

            let loaded = pump_until(
                || win.open_now().empty_note().is_some() && listening_row_for(&win, port).is_some(),
                DEADLINE,
            );
            if !loaded {
                seen.replace(Some((false, false, false)));
                return;
            }
            let index = listening_row_for(&win, port).expect("just checked");
            let openable = win.listening().open_button_for(index).is_some();

            *rules.lock().expect("not poisoned") = vec![wire_rule(port)];
            connection
                .emit_signal(
                    None::<()>,
                    PATH,
                    INTERFACE,
                    "RuleOpened",
                    &(wire_rule(port),),
                )
                .expect("the stand-in can emit");

            let shown = pump_until(|| win.open_now().rows().len() == 1, DEADLINE);
            seen.replace(Some((true, openable, shown)));
            // So the next case's window is the only one listening.
            win.close();
        },
    );

    let (loaded, openable, shown) = result.borrow_mut().take().ok_or("activation never ran")?;
    drop(listener);
    if !loaded {
        return Err(
            "the window never settled on a confirmed-empty rule list with a Listening row for \
             the socket this test bound"
                .to_string(),
        );
    }
    if !openable {
        return Err(
            "a port nothing reports open must have an Open button on its Listening row, or this \
             check cannot tell it being withheld later from its never having been there"
                .to_string(),
        );
    }
    if !shown {
        return Err(
            "the helper announced an open and the window went on showing nothing open".to_string(),
        );
    }
    Ok(())
}

/// A window the user has closed stops listening.
///
/// The subscription is a task on the main context holding the window, and
/// the expiry callback left on "Open now" holds it too; both are released by
/// the window's own `close-request` handler. This drives that handler for
/// real, through `gtk::Window::close` -- the same signal the window
/// manager's close button raises -- and then checks the one observable
/// consequence: an announcement after the window is closed changes nothing
/// on it. `SourceId::remove` on a source that has already finished is a
/// panic, so a teardown that got its bookkeeping wrong ends this process
/// rather than failing quietly.
///
/// The wait here is deliberately short and its expected answer is "no". This
/// is asserting that nothing happens, and every other case in this file
/// already proves something does while the window is open.
///
/// `close`, not `destroy`, and that is measured rather than preferred: on a
/// real presented window in this container, `destroy` emitted no `destroy`
/// signal for a handler to run on -- see
/// `PortholeWindow::start_listening`'s own comment for what holds the
/// references that keeps it from being emitted.
fn a_closed_window_stops_listening(
    connection: &zbus::blocking::Connection,
    rules: &Rules,
) -> Result<(), String> {
    /// Long enough for a refresh that was going to happen to have happened:
    /// the announcement is coalesced for 200ms and the round trip is to a
    /// stand-in in this same process.
    const NOTHING_HAPPENS: Duration = Duration::from_secs(3);

    let listener = TcpListener::bind(("0.0.0.0", 0)).map_err(|e| format!("no listener: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("no local address: {e}"))?
        .port();
    *rules.lock().expect("not poisoned") = vec![wire_rule(port)];

    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    let connection = connection.clone();
    let rules = rules.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ClosedWindow",
        move |app| {
            let win = PortholeWindow::new(app);
            win.present();
            let loaded = pump_until(|| win.open_now().rows().len() == 1, DEADLINE);
            if !loaded {
                seen.replace(Some((false, false)));
                return;
            }

            win.close();
            pump_until(|| false, Duration::from_millis(200));

            rules.lock().expect("not poisoned").clear();
            connection
                .emit_signal(
                    None::<()>,
                    PATH,
                    INTERFACE,
                    "RuleClosed",
                    &(wire_rule(port), CloseReason::Expired),
                )
                .expect("the stand-in can emit");

            let reacted = pump_until(|| win.open_now().rows().is_empty(), NOTHING_HAPPENS);
            seen.replace(Some((true, reacted)));
        },
    );

    let (loaded, reacted) = result.borrow_mut().take().ok_or("activation never ran")?;
    drop(listener);
    if !loaded {
        return Err("the window never showed the stand-in helper's rule".to_string());
    }
    if reacted {
        return Err(
            "a closed window still re-read the helper's list, so its subscription outlived it"
                .to_string(),
        );
    }
    Ok(())
}

/// One named check, run by `main` -- the same shape `tests/window.rs` uses,
/// with the bus handles every case here needs threaded through.
type Case = (
    &'static str,
    fn(&zbus::blocking::Connection, &Rules) -> Result<(), String>,
);

fn main() {
    // Before any window exists: the window reaches the helper on the
    // *system* bus, and the only daemon in this container is the private
    // session one `dbus-run-session` started. See this file's own module
    // doc.
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .expect("gui-test.sh runs this target under dbus-run-session");
    std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", &address);

    let rules: Rules = Arc::new(Mutex::new(Vec::new()));
    // One connection for the whole file: the well-known name can only be
    // owned once at a time, and a per-case connection would race its
    // successor for it.
    let connection = zbus::blocking::connection::Builder::address(address.as_str())
        .expect("a bus address")
        .name(SERVICE)
        .expect("a valid well-known name")
        .serve_at(
            PATH,
            StandInHelper {
                rules: rules.clone(),
            },
        )
        .expect("a valid object path")
        .build()
        .expect("the stand-in helper can take the name");

    let cases: [Case; 3] = [
        (
            "a_rule_closed_elsewhere_leaves_the_window_and_frees_its_listening_row",
            a_rule_closed_elsewhere_leaves_the_window_and_frees_its_listening_row,
        ),
        (
            "a_rule_opened_elsewhere_appears_without_the_window_asking",
            a_rule_opened_elsewhere_appears_without_the_window_asking,
        ),
        (
            "a_closed_window_stops_listening",
            a_closed_window_stops_listening,
        ),
    ];

    let failed = Cell::new(false);
    for (name, case) in cases {
        match case(&connection, &rules) {
            Ok(()) => println!("test {name} ... ok"),
            Err(message) => {
                println!("test {name} ... FAILED: {message}");
                failed.set(true);
            }
        }
    }

    if failed.get() {
        std::process::exit(1);
    }
}
