//! What the window does about a helper it cannot read.
//!
//! The defect measured on 2026-09-09: the forward feature added three
//! members to `WireRule`, so `list`'s return went from `a(sqssssttu)` to
//! `a(sqssssttusqq)`, and a component built against one talking to a helper
//! built against the other gets `zbus::Error::Variant(SignatureMismatch)`.
//! That is not a `zbus::Error::MethodError`, so this window classified it as
//! "could not reach the porthole helper" -- about a helper that had just
//! answered -- and went on offering every button, including the ones whose
//! **request** a mismatched helper still accepts. `open`'s arguments did not
//! change: a stale window pressing Open really opens the port and cannot
//! read the reply that says so.
//!
//! Its own `[[test]]` target for two reasons, both process-wide. The first
//! is the one `tests/signals.rs` already gives: `DBUS_SYSTEM_BUS_ADDRESS` is
//! pointed at the private session bus `gui-test.sh` runs everything under,
//! and every other target here depends on there being no system bus at all.
//! The second is this file's own: the stand-in helper here serves the
//! **previous** shape of `WireRule`, and a well-known name can only be owned
//! by one connection at a time -- so it cannot share `tests/signals.rs`'s
//! helper, which serves the current one.
//!
//! Nothing here touches this machine's real buses, and neither stand-in
//! opens anything: they answer reads with fixtures.

use std::cell::{Cell, RefCell};
use std::net::TcpListener;
use std::rc::Rc;
use std::time::{Duration, Instant};

use adw::prelude::*;
use porthole_core::ipc::{WireDockerPort, WireRule, WireStatus, PATH, PROTOCOL_VERSION, SERVICE};
use porthole_gui::window::PortholeWindow;

/// How long any of these will wait for the bus and a widget to settle.
/// Generous on purpose: a software-rendered GTK window in a container under
/// a cold cargo build is not the thing under test.
const DEADLINE: Duration = Duration::from_secs(20);

const OPENED_AT: u64 = 1_757_100_000;
const EXPIRES_AT: u64 = 1_757_103_600;

/// Runs `f` inside a real `adw::Application` activation -- the same helper
/// every GTK-touching file here carries, for the same reason: the widgets
/// have to be built inside a real activation.
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

/// Drains the main context until `condition` holds, or `timeout` elapses.
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

/// `WireRule` as it was before the forward feature -- nine members, not
/// twelve. Spelled out rather than derived from `WireRule`, which would
/// follow it forward and stop being the old shape.
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

/// And `WireStatus` as it was, which carries the same rules -- so a helper
/// from before the upgrade answers *both* of this window's first two reads
/// in a shape it cannot read, exactly as a real one would.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zbus::zvariant::Type)]
struct StatusBeforeForward {
    backend: String,
    firewall_available: bool,
    firewall_active: bool,
    firewall_active_unknown: bool,
    firewall_version: String,
    detail: String,
    location: String,
    interface: String,
    address: String,
    cidr: String,
    rules: Vec<RuleBeforeForward>,
}

fn rule_before_forward(port: u16) -> RuleBeforeForward {
    RuleBeforeForward {
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

/// A helper from before the forward feature. It has no `docker_ports` at
/// all, because that method arrived with the same change -- so this is not a
/// helper with one method rewritten, it is the interface as it stood.
struct HelperFromBeforeForward;

#[zbus::interface(name = "com.jacopobriccola.Porthole1")]
impl HelperFromBeforeForward {
    async fn list(&self) -> Vec<RuleBeforeForward> {
        vec![rule_before_forward(5173)]
    }

    async fn status(&self) -> StatusBeforeForward {
        StatusBeforeForward {
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
            rules: vec![rule_before_forward(5173)],
        }
    }
}

/// The same three reads in the shape this build is compiled against -- the
/// positive control, so that "the window disabled itself" is a thing this
/// harness can tell apart from "the window never worked".
struct CurrentHelper;

#[zbus::interface(name = "com.jacopobriccola.Porthole1")]
impl CurrentHelper {
    async fn list(&self) -> Vec<WireRule> {
        vec![WireRule {
            id: "5173/tcp".to_string(),
            port: 5173,
            protocol: "tcp".to_string(),
            target: "10.10.10.0/24".to_string(),
            scope: "network".to_string(),
            backend: "firewalld".to_string(),
            opened_at: OPENED_AT,
            expires_at: EXPIRES_AT,
            uid: 1000,
            container_addr: String::new(),
            container_port: 0,
            published_port: 0,
        }]
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
            rules: Vec::new(),
        }
    }

    async fn docker_ports(&self) -> Vec<WireDockerPort> {
        Vec::new()
    }

    /// The ordinary configuration: one package, one protocol, both halves
    /// speaking it.
    async fn protocol_version(&self) -> u32 {
        PROTOCOL_VERSION
    }
}

/// A helper **newer** than this window: it answers in a shape this build
/// cannot read, and its `ProtocolVersion` says which of the two that makes
/// the older half.
///
/// The unreadable shape here is the one from *before* the forward feature,
/// because that is the only shape this repository can write down -- a future
/// `WireRule` is by definition one this build does not have. What is being
/// stood in for is the property that matters and nothing else: an answer this
/// window cannot decode, from a helper whose own version is ahead of it.
struct HelperFromTheFuture;

#[zbus::interface(name = "com.jacopobriccola.Porthole1")]
impl HelperFromTheFuture {
    async fn list(&self) -> Vec<RuleBeforeForward> {
        vec![rule_before_forward(5173)]
    }

    async fn status(&self) -> StatusBeforeForward {
        StatusBeforeForward {
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
            rules: vec![rule_before_forward(5173)],
        }
    }

    async fn protocol_version(&self) -> u32 {
        PROTOCOL_VERSION + 1
    }
}

/// What one case reads back off the real widgets.
#[derive(Debug, Default, Clone)]
struct Seen {
    settled: bool,
    banner_showing: bool,
    banner_text: String,
    line_text: String,
    note_title: String,
    note_description: String,
    open_button_pressable: bool,
    /// Whether the row for the socket this case really bound exists at all
    /// -- without it, `listening_pressable` below is a check that ran
    /// nothing. Measured: in this container nothing else is listening on a
    /// network interface, so a case that did not bind its own socket found
    /// no rows, and asserting over an empty list passed with the disabling
    /// removed.
    listening_row_found: bool,
    listening_pressable: bool,
    window_still_there: bool,
    menu_still_reachable: bool,
}

/// Which "Listening" row is the socket a case bound, by the port in its own
/// title (`"<process> · <port>"`, or the bare port when the owning process
/// could not be identified) -- the same lookup `tests/signals.rs` makes, for
/// the same reason: the port comes from the kernel, so no other row in the
/// container can share it.
fn listening_row_for(win: &PortholeWindow, port: u16) -> Option<usize> {
    let suffix = format!("· {port}");
    let bare = port.to_string();
    win.listening().rows().iter().position(|row| {
        let title = row.title().to_string();
        title == bare || title.ends_with(&suffix)
    })
}

fn look_at_the_window(
    app: &adw::Application,
    port: u16,
    settled: impl Fn(&PortholeWindow) -> bool,
) -> Seen {
    let win = PortholeWindow::new(app);
    win.present();
    let settled = pump_until(
        || settled(&win) && listening_row_for(&win, port).is_some(),
        DEADLINE,
    );
    // Whether the button on that row can still be pressed. `is_sensitive` is
    // GTK's *effective* sensitivity -- the widget's own flag and every
    // ancestor's -- so a row rebuilt inside a section switched off after the
    // fact answers `false` here without this having to find it.
    let row = listening_row_for(&win, port);
    let listening_pressable = row
        .and_then(|i| win.listening().open_button_for(i))
        .map(|b| b.is_sensitive())
        .unwrap_or(false);
    let seen = Seen {
        settled,
        banner_showing: win.status_bar().is_prominent(),
        banner_text: win.status_bar().text(),
        line_text: win.status_bar().line_widget().label().to_string(),
        note_title: win
            .open_now()
            .error_note()
            .map(|n| n.title())
            .unwrap_or_default(),
        note_description: win
            .open_now()
            .error_note()
            .and_then(|n| n.description())
            .unwrap_or_default(),
        open_button_pressable: win.open_button().is_sensitive(),
        listening_row_found: row.is_some(),
        listening_pressable,
        window_still_there: win.is_visible(),
        menu_still_reachable: win.menu_button().is_sensitive(),
    };
    win.close();
    seen
}

/// A real socket on a real port, so the "Listening" section has a real row
/// with a real Open button on it -- the same device `tests/signals.rs` uses,
/// and for a reason measured here: without it there are no rows in this
/// container at all.
fn bind_a_listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind("0.0.0.0:0").expect("a port from the kernel");
    let port = listener.local_addr().expect("a bound address").port();
    (listener, port)
}

/// A helper this build cannot read: the window says so and stops offering
/// anything that would reach it -- and stays on screen while it does.
fn a_helper_this_build_cannot_read_disables_the_window_and_says_why() -> Result<(), String> {
    let (_listener, port) = bind_a_listener();
    let seen = Rc::new(RefCell::new(Seen::default()));
    let out = seen.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.VersionMismatch",
        move |app| {
            *out.borrow_mut() = look_at_the_window(app, port, |win| {
                // Settled when the banner is up: every path out of a refresh
                // ends either there or in an ordinary status line.
                win.status_bar().is_prominent()
            });
        },
    );
    let seen = seen.borrow().clone();

    if !seen.settled {
        return Err(format!(
            "the window never said anything prominent at all -- status line: {:?}",
            seen.banner_text
        ));
    }
    if !seen.banner_showing {
        return Err("nothing prominent is showing".to_string());
    }
    if seen.banner_text.to_lowercase().contains("could not reach") {
        return Err(format!(
            "the helper answered; this is the false claim the fix removes: {:?}",
            seen.banner_text
        ));
    }
    if !seen.banner_text.contains("older version") || !seen.banner_text.contains("cannot read") {
        return Err(format!(
            "the banner has to say what is actually wrong -- a version difference, and \
             which side of it this window is on: {:?}",
            seen.banner_text
        ));
    }
    // One remedy, and the right one. This stand-in has no `ProtocolVersion`
    // member at all -- which is what every helper deployed today answers,
    // measured read-only against the live one on the author's own machine --
    // and an absent member is a helper from before that contract, so the
    // older half is the helper. Before the version was on the wire this
    // banner had to offer both and let the person try them in turn.
    if !seen
        .banner_text
        .contains("systemctl restart porthole-helper.service")
    {
        return Err(format!(
            "the banner must name the half the version identified: {:?}",
            seen.banner_text
        ));
    }
    if seen
        .banner_text
        .to_lowercase()
        .contains("reopen this window")
    {
        return Err(format!(
            "and stop offering the window's own remedy, which would start this same \
             version again: {:?}",
            seen.banner_text
        ));
    }
    if !seen.line_text.contains("ignature") {
        return Err(format!(
            "zbus's own text, which is what names the two signatures, must survive to the \
             line underneath: {:?}",
            seen.line_text
        ));
    }
    if !seen.note_title.contains("could not read") {
        return Err(format!(
            "\"Open now\" must say the same thing in its own words: {:?}",
            seen.note_title
        ));
    }
    if !seen.note_description.contains("ignature") {
        return Err(format!(
            "and carry the reason verbatim: {:?}",
            seen.note_description
        ));
    }

    // The half that is not cosmetic: `open`'s *arguments* did not change, so
    // a press here would really open a port whose confirmation this window
    // could not read.
    if seen.open_button_pressable {
        return Err(
            "\"Open a port\" is still pressable against a helper this window \
                    cannot read"
                .to_string(),
        );
    }
    if !seen.listening_row_found {
        return Err(
            "the socket this case bound has no row, so nothing was checked about a row's \
             own button"
                .to_string(),
        );
    }
    if seen.listening_pressable {
        return Err(
            "a \"Listening\" row still offers a button that would reach the helper".to_string(),
        );
    }

    // And the half that separates this from `porthole-agent`'s answer: the
    // window does not vanish under the user's hands.
    if !seen.window_still_there {
        return Err("the window disappeared instead of saying anything".to_string());
    }
    if !seen.menu_still_reachable {
        return Err(
            "the saved-devices menu never reaches the helper and must go on working".to_string(),
        );
    }
    Ok(())
}

/// The positive control, in this same process and through the same code:
/// against a helper it *can* read, the window populates and every button
/// works. Without it, the case above would pass just as well against a
/// window that had never worked at all.
fn the_same_window_against_a_helper_it_can_read_is_not_disabled() -> Result<(), String> {
    let (_listener, port) = bind_a_listener();
    let seen = Rc::new(RefCell::new(Seen::default()));
    let out = seen.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.VersionMatch",
        move |app| {
            *out.borrow_mut() =
                look_at_the_window(app, port, |win| !win.open_now().rows().is_empty());
        },
    );
    let seen = seen.borrow().clone();

    if !seen.settled {
        return Err("the window never showed the rule the helper reported".to_string());
    }
    if seen.banner_showing {
        return Err(format!(
            "nothing is wrong here, and the window says something is: {:?}",
            seen.banner_text
        ));
    }
    if !seen.open_button_pressable {
        return Err("\"Open a port\" is not pressable against a working helper".to_string());
    }
    if !seen.listening_row_found {
        return Err("the socket this case bound has no row at all".to_string());
    }
    // The half that makes the case above mean something: this very row, in
    // this very container, really does carry a pressable button when nothing
    // is wrong. Without it, "the button is unpressable" over there could be
    // a button that is never pressable.
    if !seen.listening_pressable {
        return Err(
            "the row for this case's own socket offers nothing against a working helper, so \
             the disabled-button check has nothing to disable"
                .to_string(),
        );
    }
    Ok(())
}

/// The other half of the same question: a helper **newer** than this
/// window, whose own version says the window is the half to replace.
///
/// A window cannot re-execute itself while somebody is using it -- that is
/// the recorded choice for this component, and it is why `porthole-agent`
/// replaces itself and this does not. So what changes here is only the
/// sentence: it names the one remedy the person has to perform instead of
/// two for them to try in turn.
fn a_helper_newer_than_this_window_says_the_window_is_the_half_to_replace() -> Result<(), String> {
    let (_listener, port) = bind_a_listener();
    let seen = Rc::new(RefCell::new(Seen::default()));
    let out = seen.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.WindowIsOlder",
        move |app| {
            *out.borrow_mut() =
                look_at_the_window(app, port, |win| win.status_bar().is_prominent());
        },
    );
    let seen = seen.borrow().clone();

    if !seen.settled || !seen.banner_showing {
        return Err(format!(
            "the window said nothing prominent about a helper it cannot read: {:?}",
            seen.banner_text
        ));
    }
    if !seen.banner_text.to_lowercase().contains("reopen") {
        return Err(format!(
            "the window is the older half here, and reopening it is what starts the \
             version that is installed: {:?}",
            seen.banner_text
        ));
    }
    if seen.banner_text.contains("porthole-helper.service") {
        return Err(format!(
            "the helper is the newer half; restarting it would change nothing: {:?}",
            seen.banner_text
        ));
    }
    if seen.banner_text.to_lowercase().contains("could not reach") {
        return Err(format!("the helper answered: {:?}", seen.banner_text));
    }
    // Everything that is not the wording is unchanged: this is the same
    // stopped window as the case above, and a banner that named a remedy
    // while leaving the buttons live would be the worse of the two failures.
    if seen.open_button_pressable {
        return Err(
            "\"Open a port\" is still pressable against a helper this window \
                    cannot read"
                .to_string(),
        );
    }
    if !seen.window_still_there {
        return Err("the window disappeared instead of saying anything".to_string());
    }
    Ok(())
}

fn main() {
    // Before any window exists -- see this file's own module doc.
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .expect("gui-test.sh runs this target under dbus-run-session");
    std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", &address);

    let stale = zbus::blocking::connection::Builder::address(address.as_str())
        .expect("a bus address")
        .serve_at(PATH, HelperFromBeforeForward)
        .expect("a valid object path")
        .build()
        .expect("a connection");
    let current = zbus::blocking::connection::Builder::address(address.as_str())
        .expect("a bus address")
        .serve_at(PATH, CurrentHelper)
        .expect("a valid object path")
        .build()
        .expect("a connection");
    let newer = zbus::blocking::connection::Builder::address(address.as_str())
        .expect("a bus address")
        .serve_at(PATH, HelperFromTheFuture)
        .expect("a valid object path")
        .build()
        .expect("a connection");

    let failed = Cell::new(false);
    let run = |name: &str, case: fn() -> Result<(), String>| match case() {
        Ok(()) => println!("test {name} ... ok"),
        Err(message) => {
            println!("test {name} ... FAILED: {message}");
            failed.set(true);
        }
    };

    // One name, two owners, one at a time: which of the two shapes the
    // window meets is decided by who holds `com.jacopobriccola.Porthole`
    // when it calls.
    stale
        .request_name(SERVICE)
        .expect("the stand-in from before the upgrade can take the name");
    run(
        "a_helper_this_build_cannot_read_disables_the_window_and_says_why",
        a_helper_this_build_cannot_read_disables_the_window_and_says_why,
    );
    stale.release_name(SERVICE).expect("and can give it back");
    current
        .request_name(SERVICE)
        .expect("the current-shape stand-in can take it");
    run(
        "the_same_window_against_a_helper_it_can_read_is_not_disabled",
        the_same_window_against_a_helper_it_can_read_is_not_disabled,
    );
    current
        .release_name(SERVICE)
        .expect("and can give it back too");
    newer
        .request_name(SERVICE)
        .expect("the stand-in from after this build can take it");
    run(
        "a_helper_newer_than_this_window_says_the_window_is_the_half_to_replace",
        a_helper_newer_than_this_window_says_the_window_is_the_half_to_replace,
    );

    if failed.get() {
        std::process::exit(1);
    }
}
