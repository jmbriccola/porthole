//! The application's single window.
//!
//! `PortholeWindow` wraps a real `adw::ApplicationWindow` rather than
//! subclassing one: nothing here needs a custom GObject property or signal,
//! only a widget tree and three stable extension points -- the `content`
//! box that Tasks 3-6 append their sections into, one per task; the narrow-
//! width `AdwBreakpoint` the spec requires (`INITIAL_PROMPT.md` §5:
//! "finestra ridimensionabile fino a larghezze strette (`AdwBreakpoint`)");
//! and the `AdwToastOverlay` any section can show a toast through, first
//! used by Task 3's close button.
//!
//! `Deref` to the real window is what makes `.present()`, `.is_realized()`,
//! `.current_breakpoint()` and every other `gtk::Window`/`gtk::Widget`/
//! `AdwApplicationWindowExt` method usable directly on a `PortholeWindow`,
//! exactly as they would be on the `adw::ApplicationWindow` itself.
//!
//! **A breakpoint only evaluates against a window's real geometry**, and
//! `set_default_size` after a window has already been `present()`-ed is
//! unreliable -- confirmed in a container: calling it on an already-wide,
//! already-presented window did not bring the actual allocated width
//! anywhere near the requested value, and `current_breakpoint()` stayed
//! `None`. So a test that wants to see this breakpoint apply has to size the
//! window narrow *before* its first `present()`, not resize it afterwards;
//! see `tests/window.rs` for exactly that sequence.
//!
//! ## The initial load -- a planning defect, repaired here
//!
//! No task before this one wired the initial data load: as this plan was
//! written, the seven tasks together produced a window that opens empty
//! and never populates. Task 3's implementer found this and deliberately
//! left [`PortholeWindow::open_now`] as the accessor for it rather than
//! widening task 3's own scope; task 4 left [`PortholeWindow::listening`]
//! the same way; task 5 left `OpenDialog::on_opened` uncalled for the
//! identical reason. This task is what finally calls all three: the free
//! function `refresh` (module-private -- reached through
//! [`PortholeWindow::refresh`] and run once at the end of
//! [`PortholeWindow::new`]) populates "Open now" and the status line from
//! the helper's own `list`/`status` over D-Bus, and "Listening" from
//! `porthole_core::listening::scan`, and the same function runs again
//! every time [`OpenDialog::on_opened`] fires -- wired onto both the
//! header bar's own "Open a port" button and every "Listening" row's
//! pre-filled one, through `present_open_dialog`.
//!
//! Neither read blocks the UI thread, and the helper round trip is bounded
//! by [`HELPER_TIMEOUT`] (zbus proxies carry no default one of their own).
//! No answer at all, a typed error the helper did answer with, and a
//! confirmed empty list are three different facts and render as three
//! different things -- see `refresh`'s own doc comment, `open_now.rs`'s and
//! `status_bar.rs`'s module docs for why conflating any pair of them is
//! this project's characteristic defect.
//!
//! ## The saved devices and Docker's own ports
//!
//! Two more things `refresh` reads: the saved devices (the address book,
//! plus a resolution attempt per device -- subprocesses, so on the same I/O
//! thread pool the `/proc` scan uses) and the ports Docker publishes (the
//! helper's own `docker_ports`, authorized by the same polkit action
//! `list` and `status` are). Both go into [`Sections`]'s own caches, and
//! [`present_open_dialog`] hands them to each [`OpenDialog`] it opens: the
//! devices become target rows, and the Docker list is what lets pressing
//! Open explain a Docker-managed port before sending anything.
//!
//! The Docker list additionally reaches the "Listening" section, which
//! marks the rows it names, and which says under its own group title which
//! of the three things an unmarked row means. The devices have their own
//! such state, the open dialog's group description. porthole never touches
//! Docker's rules; every one of these surfaces only ever reads and
//! explains.

use std::cell::RefCell;
use std::ops::Deref;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use porthole_core::command::RealRunner;
use porthole_core::devices;
use porthole_core::docker::Published;
use porthole_core::ipc::{PortholeProxy, WireDockerPort, WireRule, WireStatus};
use porthole_core::listening::RealProcFs;

use crate::listening_section::ListeningSection;
use crate::open_dialog::{DeviceEntry, OpenDialog};
use crate::open_now::OpenNowSection;
use crate::status_bar::StatusBar;

/// The saved devices as [`load_devices`] last resolved them, or the reason
/// the address book itself could not be read -- two facts an empty `Vec`
/// alone cannot tell apart, and the second of which must not render as "no
/// devices are saved".
type DeviceSnapshot = Result<Vec<DeviceEntry>, String>;

/// What [`refresh`] fills in, and what it keeps for an [`OpenDialog`]
/// opened later. One value rather than six parameters threaded through four
/// functions; every field is a refcounted handle, so a clone is another
/// handle on the same thing, not a copy of it.
#[derive(Clone)]
struct Sections {
    window: adw::ApplicationWindow,
    open_now: OpenNowSection,
    listening: ListeningSection,
    status_bar: StatusBar,
    /// Read on a worker thread by [`refresh`], and read back by
    /// [`present_open_dialog`] when a dialog is actually opened -- the
    /// dialog never resolves a device itself, and never blocks on one.
    devices: Rc<RefCell<DeviceSnapshot>>,
    /// Every port Docker publishes, or `None` for "there is no checked
    /// list" -- whether because nothing has come back yet or because what
    /// came back had no answer. Not an empty `Vec`: only a list that
    /// arrived can tell a port Docker does not publish from one nobody
    /// checked. The [`OpenDialog`] this feeds explains nothing about Docker
    /// in either `None` case, so it needs no finer distinction than this;
    /// the "Listening" section does, and keeps its own.
    docker: Rc<RefCell<Option<Vec<Published>>>>,
}

/// The width, in CSS pixels, at or below which the narrow layout applies.
/// The `Breakpoint` object itself is reachable via
/// [`PortholeWindow::breakpoint`]; task 6 is what attaches its first real
/// layout change, `NARROW_MARGIN_PX` below, through `Breakpoint::add_setters`
/// during construction -- a registered breakpoint with no setter attached
/// activates and changes nothing, which is what this crate shipped until
/// that call existed.
const NARROW_WIDTH_PX: f64 = 400.0;

/// `content`'s own margin, in CSS pixels, while the window is narrow --
/// down from the ordinary 24px set at construction. Applied through
/// `Breakpoint::add_setters` during construction; libadwaita restores the
/// original 24px on its own once the breakpoint stops matching.
const NARROW_MARGIN_PX: i32 = 12;

pub struct PortholeWindow {
    window: adw::ApplicationWindow,
    content: gtk::Box,
    breakpoint: adw::Breakpoint,
    toast_overlay: adw::ToastOverlay,
    open_now: OpenNowSection,
    listening: ListeningSection,
    status_bar: StatusBar,
    open_button: gtk::Button,
    devices: Rc<RefCell<DeviceSnapshot>>,
    docker: Rc<RefCell<Option<Vec<Published>>>>,
}

impl Deref for PortholeWindow {
    type Target = adw::ApplicationWindow;

    fn deref(&self) -> &Self::Target {
        &self.window
    }
}

impl PortholeWindow {
    pub fn new(app: &adw::Application) -> Self {
        let window = Self::build(app);
        // The initial load this constructor owes -- see this module's own
        // doc comment on the planning defect this task repairs. Both
        // sections start out showing their own *indeterminate* "not
        // answered yet" state (built into `OpenNowSection`/
        // `ListeningSection` themselves, not the calm "nothing open"/
        // "nothing listening" one -- a zbus proxy carries no default
        // per-call timeout, so nothing bounds how long that would
        // otherwise have to stand in for a confirmed fact it has not
        // earned) until `refresh` resolves; `refresh` runs the same path a
        // later explicit refresh does, there is no separate "first load"
        // code.
        refresh(&window.sections());
        window
    }

    /// Builds the same window [`PortholeWindow::new`] does, but never
    /// starts the initial helper/`/proc` load -- for `main.rs`'s
    /// debug-only `--screenshot` flag (`crate::screenshot::run`), which
    /// populates the window with fixture data instead of real data, and
    /// needs nothing in this crate racing that fixture for which one lands
    /// on screen last. Every other caller wants [`PortholeWindow::new`],
    /// not this.
    pub fn new_without_initial_load(app: &adw::Application) -> Self {
        Self::build(app)
    }

    fn build(app: &adw::Application) -> Self {
        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(18)
            .margin_top(24)
            .margin_bottom(24)
            .margin_start(24)
            .margin_end(24)
            .build();

        let scroller = gtk::ScrolledWindow::builder()
            .child(&content)
            .vexpand(true)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .build();

        // Wraps the scrollable content area only, not the header bar, so a
        // toast (e.g. a failed close, Task 3's close button) never covers
        // window chrome.
        let toast_overlay = adw::ToastOverlay::new();
        toast_overlay.set_child(Some(&scroller));

        let status_bar = StatusBar::new();

        // Task 5's own affordance: opens a fresh `OpenDialog` -- never a
        // reused one, so a previous attempt's typed port or chosen chip
        // never leaks into the next. `ListeningSection`'s own per-row Open
        // buttons are the second, pre-filled way to reach the same dialog;
        // both are wired through `present_open_dialog` below, once real
        // data exists to wire the row buttons onto (see `refresh`).
        let open_button = gtk::Button::builder()
            .icon_name("list-add-symbolic")
            .tooltip_text("Open a port")
            .build();
        let header_bar = adw::HeaderBar::new();
        header_bar.pack_start(&open_button);

        let toolbar_view = adw::ToolbarView::new();
        toolbar_view.add_top_bar(&header_bar);
        // Right below the header when it has something prominent to say
        // (no firewall at all, or the helper unreachable); zero height
        // otherwise. See `status_bar.rs`'s own module doc for why that
        // case cannot share the ordinary bottom-bar line below.
        toolbar_view.add_top_bar(status_bar.banner_widget());
        toolbar_view.set_content(Some(&toast_overlay));
        toolbar_view.add_bottom_bar(status_bar.line_widget());

        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("Porthole")
            .default_width(480)
            .default_height(560)
            .content(&toolbar_view)
            .build();

        let condition = adw::BreakpointCondition::new_length(
            adw::BreakpointConditionLengthType::MaxWidth,
            NARROW_WIDTH_PX,
            adw::LengthUnit::Px,
        );
        let breakpoint = adw::Breakpoint::new(condition);
        // The layout change this task attaches: `content`'s own margins
        // shrink from the ordinary 24px down to `NARROW_MARGIN_PX` while
        // the window is narrow, reclaiming real width for the rows inside
        // it -- and back to 24px the moment the breakpoint stops matching,
        // which `add_setters` restores on its own. A registered breakpoint
        // with no setter activates and changes nothing; earlier drafts of
        // this task left it exactly that inert, which
        // `tests/window.rs`'s own margin test now catches.
        breakpoint.add_setters(&[
            (&content, "margin-top", NARROW_MARGIN_PX),
            (&content, "margin-bottom", NARROW_MARGIN_PX),
            (&content, "margin-start", NARROW_MARGIN_PX),
            (&content, "margin-end", NARROW_MARGIN_PX),
        ]);
        // `AdwApplicationWindowExt::add_breakpoint` takes ownership of the
        // `Breakpoint`, but it is a refcounted GObject handle like every
        // other widget here -- cloning keeps a second handle in `self` so
        // callers (Tasks 3-6, and this crate's own tests) can still reach
        // the exact object that was registered.
        window.add_breakpoint(breakpoint.clone());

        // "Open now" -- what is open comes before what could be opened, the
        // spec's own ordering. Wired to this window's toast overlay so a
        // failed close (the helper's own message) has somewhere to show up.
        let open_now = OpenNowSection::new();
        open_now.set_toast_overlay(&toast_overlay);
        content.append(open_now.widget());

        // "Listening" -- services running on this machine that are not
        // (yet) open to the network. Placed after "Open now" for the same
        // ordering reason: what is already open comes first, what could be
        // opened next.
        let listening = ListeningSection::new();
        content.append(listening.widget());

        // The device cache starts out holding the reason there is nothing
        // in it, not an empty list of devices. The Docker cache has no such
        // distinction to make and needs none: the open dialog it feeds says
        // nothing about Docker whether the list is missing because nobody
        // asked or because the helper could not answer. The section that
        // *does* have to tell those two apart keeps its own state -- see
        // `listening_section::DockerPorts`, and `apply_docker` below for
        // why this constructor must not put it in the failed one.
        let devices: Rc<RefCell<DeviceSnapshot>> =
            Rc::new(RefCell::new(Err(DEVICES_NOT_READ_YET.to_string())));
        let docker: Rc<RefCell<Option<Vec<Published>>>> = Rc::new(RefCell::new(None));

        let sections_for_open = Sections {
            window: window.clone(),
            open_now: open_now.clone(),
            listening: listening.clone(),
            status_bar: status_bar.clone(),
            devices: devices.clone(),
            docker: docker.clone(),
        };
        open_button.connect_clicked(move |_| {
            present_open_dialog(&sections_for_open, &OpenDialog::new());
        });

        // What a "Listening" row's own Open button does, registered once
        // here and held by the section for as long as it exists. The
        // section connects every button it builds to this as it builds it,
        // so no caller of any setter has anything to reattach -- see
        // `listening_section.rs`'s own doc comment. It is registered here,
        // and not there, because that section knows nothing about
        // `OpenDialog` or this window.
        let sections_for_row = Sections {
            window: window.clone(),
            open_now: open_now.clone(),
            listening: listening.clone(),
            status_bar: status_bar.clone(),
            devices: devices.clone(),
            docker: docker.clone(),
        };
        listening.connect_open_requested(move |port| {
            present_open_dialog(&sections_for_row, &OpenDialog::for_port(port));
        });

        // The other direction: what a successful close in "Open now" does
        // to "Listening". That section withholds a row's Open button for a
        // port the rule list names, and a close changes that list -- so it
        // is told the list that close left behind, from the same section
        // that now holds it. Registered here, and not in `open_now.rs`,
        // for the reason the Open button's own callback is: neither
        // section holds a reference to the other.
        //
        // `set_open_ports`, not `refresh`: the rules handed over are the
        // ones "Open now" is showing, so both sections mark from one list
        // rather than from two round trips that could land in either order.
        // A close changes the rule list and nothing else this window reads
        // -- the `/proc` listeners, the ports Docker publishes, the saved
        // devices and every field of `WireStatus` are all independent of
        // it.
        let listening_for_close = listening.clone();
        open_now.connect_close_succeeded(move |remaining| {
            listening_for_close.set_open_ports(&open_tcp_ports(remaining));
        });

        // No initial `refresh` here -- see `PortholeWindow::new` (the only
        // caller that wants one) and `PortholeWindow::new_without_initial_load`
        // (the one that deliberately does not) for where that call now
        // lives and why.
        Self {
            window,
            content,
            breakpoint,
            toast_overlay,
            open_now,
            listening,
            status_bar,
            open_button,
            devices,
            docker,
        }
    }

    /// This window's own sections and caches as the one bundle `refresh`
    /// and `present_open_dialog` take. Every field is a refcounted handle:
    /// what comes back shares state with this window rather than copying
    /// it.
    fn sections(&self) -> Sections {
        Sections {
            window: self.window.clone(),
            open_now: self.open_now.clone(),
            listening: self.listening.clone(),
            status_bar: self.status_bar.clone(),
            devices: self.devices.clone(),
            docker: self.docker.clone(),
        }
    }

    /// The box Tasks 3-6 append their sections into, one per task.
    pub fn content(&self) -> &gtk::Box {
        &self.content
    }

    /// The narrow-width breakpoint registered on this window -- its own
    /// layout change (`NARROW_MARGIN_PX`) is already attached to this exact
    /// object during construction; a later section that wants a second one
    /// calls `Breakpoint::add_setters` again on what this returns.
    ///
    /// This is the same object `current_breakpoint()` (from
    /// `AdwApplicationWindowExt`, reachable via `Deref`) reports back once
    /// the window is actually narrow -- see `tests/window.rs` for a test
    /// that resizes a real window and checks exactly that.
    pub fn breakpoint(&self) -> &adw::Breakpoint {
        &self.breakpoint
    }

    /// The overlay any section can show an `adw::Toast` through. Wraps the
    /// scrollable content area, not the header bar.
    pub fn toast_overlay(&self) -> &adw::ToastOverlay {
        &self.toast_overlay
    }

    /// The "Open now" section this window owns, for a later task (or a
    /// test) that needs to feed it a fresh rule list.
    pub fn open_now(&self) -> &OpenNowSection {
        &self.open_now
    }

    /// The "Listening" section this window owns, for a later task (or a
    /// test) that needs to feed it a fresh service list.
    pub fn listening(&self) -> &ListeningSection {
        &self.listening
    }

    /// The status line this window owns -- see `status_bar.rs`'s own
    /// module doc for what it shows, and why it is two widgets rather than
    /// one.
    pub fn status_bar(&self) -> &StatusBar {
        &self.status_bar
    }

    /// The header bar's "Open a port" button, for a test that wants to
    /// check its own state (tooltip, focusability) rather than simulate a
    /// click -- see this constructor's own comment on why the click handler
    /// builds a fresh `OpenDialog` each time instead of one this window
    /// keeps around.
    pub fn open_button(&self) -> &gtk::Button {
        &self.open_button
    }

    /// Every widget this window currently has that a click can activate --
    /// a structural readback, not a hand-maintained list: the header bar's
    /// own "Open a port" button, plus every currently-rendered close
    /// button in "Open now" and every currently-rendered Open button in
    /// "Listening" (rows with neither -- an unopenable "Listening" row, an
    /// unopened "Open now" list -- contribute nothing, since there is
    /// nothing there to reach). `tests/window.rs`'s own keyboard-
    /// reachability test checks `is_focusable()` on each of these: a GNOME
    /// app that needs a mouse is not a GNOME app.
    pub fn actionable_widgets(&self) -> Vec<gtk::Button> {
        let mut widgets = vec![self.open_button.clone()];
        for index in 0..self.open_now.rows().len() {
            if let Some(button) = self.open_now.close_button_for(index) {
                widgets.push(button);
            }
        }
        for index in 0..self.listening.rows().len() {
            if let Some(button) = self.listening.open_button_for(index) {
                widgets.push(button);
            }
        }
        widgets
    }

    /// Re-populates "Open now", "Listening" and the status line from the
    /// helper and `/proc` again -- the same thing [`PortholeWindow::new`]
    /// already runs once at construction, and the same thing a successful
    /// open re-triggers through `OpenDialog::on_opened`. See the free
    /// function of the same name, below, for what it actually does and why
    /// neither read blocks the UI thread.
    pub fn refresh(&self) {
        refresh(&self.sections());
    }
}

/// The helper's own rendered text from a D-Bus method error, verbatim.
///
/// The third copy of this exact shape in this crate -- `open_now.rs` and
/// `open_dialog.rs` each carry their own, for the identical reason: the
/// helper already phrased this for a person, and rebuilding a message from
/// the error name would double or invent wording nobody asked for.
fn helper_message(e: &zbus::Error) -> String {
    if let zbus::Error::MethodError(name, detail, _) = e {
        detail.clone().unwrap_or_else(|| name.to_string())
    } else {
        e.to_string()
    }
}

/// Two different facts a `list`/`status` call can fail with, neither of
/// which may render as the other -- see `open_now.rs`'s and
/// `status_bar.rs`'s own module docs for why conflating them is this
/// project's characteristic defect. `Unreachable` is no answer at all: no
/// bus, no helper process, the connection lost mid-call, or this refresh's
/// own bounded wait (`with_timeout`, below) running out. `Errored` is the
/// helper answering with a typed error -- [`classify_failure`] is what
/// tells the two apart: only a `zbus::Error::MethodError` means the helper
/// actually responded.
///
/// `Errored` is deliberately **not** named or worded as a refusal, and an
/// earlier version of this enum got that wrong (`Refused`, rendered as "The
/// porthole helper refused this request"): `list` and `status` both go
/// through the same authorization check `open`/`close` do (see
/// `porthole-helper/src/service.rs`), so a polkit denial (`HelperError::
/// NotAuthorized`) really is a declined request and reaches here as a
/// `MethodError` same as everything else -- but so does a `StateStore`
/// read failure (`HelperError::State`) or any other error the helper's own
/// `HelperError::Failed` catch-all carries, and neither of those is a
/// decision to decline anything; they are the helper trying to answer and
/// failing. `classify_failure` does not distinguish which one occurred (the
/// wire's own error name would let a future caller do that, if it became
/// worth a fourth rendering); what changed here is only that the wording
/// no longer claims a specific one.
enum HelperFailure {
    Unreachable(String),
    Errored(String),
}

fn classify_failure(e: zbus::Error) -> HelperFailure {
    match &e {
        zbus::Error::MethodError(..) => HelperFailure::Errored(helper_message(&e)),
        _ => HelperFailure::Unreachable(format!("could not reach the porthole helper: {e}")),
    }
}

fn apply_failure_to_open_now(open_now: &OpenNowSection, failure: &HelperFailure) {
    match failure {
        HelperFailure::Unreachable(message) => open_now.set_unreachable(message),
        HelperFailure::Errored(message) => open_now.set_errored(message),
    }
}

fn apply_failure_to_status_bar(status_bar: &StatusBar, failure: &HelperFailure) {
    match failure {
        HelperFailure::Unreachable(message) => status_bar.set_unreachable(message),
        HelperFailure::Errored(message) => status_bar.set_errored(message),
    }
}

/// Everything one refresh needs from the helper: every rule `list`
/// currently reports, and the backend's own `status` -- fetched over a
/// single connection, but kept as two **independent** results rather than
/// collapsed into one `Result` for the whole snapshot. An earlier draft of
/// [`fetch_helper_snapshot`] did exactly that collapse: a `status` failure
/// discarded a `list` that had already succeeded, known-good data thrown
/// away because a second, unrelated call happened to fail. The outer
/// `Result` [`fetch_helper_snapshot`] itself returns only fails when no
/// connection or proxy could be made at all -- the one case where neither
/// call was even attempted.
struct HelperSnapshot {
    rules: Result<Vec<WireRule>, HelperFailure>,
    status: Result<WireStatus, HelperFailure>,
    docker: Result<Vec<Published>, HelperFailure>,
}

/// One [`WireDockerPort`] as the local type. `host_addr` empty means "no
/// `-d`", i.e. every interface -- see [`WireDockerPort`]'s own doc comment.
/// The same conversion `porthole-cli`'s own client makes off the same wire,
/// down to treating a malformed address as the helper's own encoding being
/// wrong rather than as anything about Docker.
fn published_from_wire(wire: &WireDockerPort) -> Result<Published, String> {
    let host_addr = if wire.host_addr.is_empty() {
        None
    } else {
        Some(wire.host_addr.parse().map_err(|_| {
            format!(
                "the helper sent `{}` as a Docker host address",
                wire.host_addr
            )
        })?)
    };
    Ok(Published {
        host_addr,
        host_port: wire.host_port,
        protocol: porthole_core::validate::parse_protocol(&wire.protocol)
            .map_err(|e| e.to_string())?,
        container_addr: wire.container_addr.parse().map_err(|_| {
            format!(
                "the helper sent `{}` as a Docker container address",
                wire.container_addr
            )
        })?,
        container_port: wire.container_port,
    })
}

async fn fetch_helper_snapshot() -> Result<HelperSnapshot, HelperFailure> {
    let connection = zbus::Connection::system().await.map_err(|e| {
        HelperFailure::Unreachable(format!("could not reach the porthole helper: {e}"))
    })?;
    let proxy = PortholeProxy::new(&connection).await.map_err(|e| {
        HelperFailure::Unreachable(format!("could not reach the porthole helper: {e}"))
    })?;
    let rules = proxy.list().await.map_err(classify_failure);
    let status = proxy.status().await.map_err(classify_failure);
    // A third independent result, for the same reason `rules` and `status`
    // are two: a `docker_ports` failure must not throw away a `list` that
    // already succeeded.
    let docker = match proxy.docker_ports().await {
        Ok(wire) => wire
            .iter()
            .map(published_from_wire)
            .collect::<Result<Vec<_>, String>>()
            .map_err(HelperFailure::Errored),
        Err(e) => Err(classify_failure(e)),
    };
    Ok(HelperSnapshot {
        rules,
        status,
        docker,
    })
}

/// What the saved-device cache says before anything has read the address
/// book -- neither a device list nor a failure to read one, and rendered as
/// itself rather than as an empty list of devices.
const DEVICES_NOT_READ_YET: &str = "porthole has not read the saved devices yet.";

/// Reads the address book and resolves every device in it, exactly as
/// `porthole devices list` does. Blocking -- `porthole_core::devices::
/// resolve` runs a subprocess per device -- so [`refresh`] runs it on
/// GLib's I/O thread pool, never on the UI thread.
///
/// Each device's own resolution failure stays that device's own -- an
/// absent phone does not hide the laptop that is here. Only the address
/// book itself failing to load produces the outer `Err`, since then there
/// are no devices to report at all.
fn load_devices() -> DeviceSnapshot {
    let book = devices::Book::load(&devices::default_path()).map_err(|e| e.to_string())?;
    let runner = RealRunner;
    Ok(book
        .devices()
        .iter()
        .map(|d| DeviceEntry {
            name: d.name.clone(),
            resolved: devices::resolve(&book, &d.name, &runner).map_err(|e| e.to_string()),
        })
        .collect())
}

/// How long [`refresh`] waits for [`fetch_helper_snapshot`] before treating
/// the helper as unreachable. zbus proxies carry no default per-call
/// timeout of their own -- against a live-but-hung helper, an unbounded
/// wait would leave both sections sitting on their own indeterminate "not
/// answered yet" state (`OpenNowSection`'s and `ListeningSection`'s own
/// `loading_page`) forever, rather than ever settling into a state a user
/// can act on.
const HELPER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Races `fut` against a real wall-clock timeout: `Some(output)` if `fut`
/// resolves first, `None` if `timeout` elapses first. No new dependency for
/// one call site -- a small hand-rolled `poll_fn` combinator over `fut` and
/// `glib::timeout_future`, which integrates with the same GLib main context
/// `glib::spawn_future_local` already runs everything in this crate on, so
/// this still never blocks that context either.
async fn with_timeout<F: std::future::Future>(
    fut: F,
    timeout: std::time::Duration,
) -> Option<F::Output> {
    let mut fut = std::pin::pin!(fut);
    let mut timer = glib::timeout_future(timeout);
    std::future::poll_fn(move |cx| {
        if let std::task::Poll::Ready(value) = fut.as_mut().poll(cx) {
            return std::task::Poll::Ready(Some(value));
        }
        if timer.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(None);
        }
        std::task::Poll::Pending
    })
    .await
}

/// Presents `dialog`, transient for `window`, and registers its
/// `on_opened` hook -- task 5's own hook, left uncalled until this task,
/// see this module's own doc comment -- to run [`refresh`] again on a
/// successful open. Shared by the header bar's own "Open a port" button
/// and every "Listening" row's pre-filled one, so both paths refresh the
/// same way.
fn present_open_dialog(sections: &Sections, dialog: &OpenDialog) {
    // Whatever the last `refresh` learned, handed over before the dialog is
    // ever on screen: the saved devices it offers as targets, and the ports
    // Docker publishes, which is what lets pressing Open explain a
    // Docker-managed port before sending anything. Both are read here, from
    // a cache, rather than fetched by the dialog -- resolving a device runs
    // a subprocess, and the dialog must not block on one at the moment it
    // opens.
    match sections.devices.borrow().as_ref() {
        Ok(entries) => dialog.set_devices(entries),
        Err(reason) => dialog.set_devices_unreadable(reason),
    }
    match sections.docker.borrow().as_ref() {
        Some(published) => dialog.set_docker_ports(published),
        None => dialog.set_docker_unknown(),
    }

    let sections_for_refresh = sections.clone();
    dialog.on_opened(move |_rule| {
        refresh(&sections_for_refresh);
    });
    dialog.present(Some(&sections.window));
}

/// Which ports [`ListeningSection::set_open_ports`] is given: the TCP ones,
/// and only those. That section reads the list to withhold a row's Open
/// button and print "already open", and `porthole_core::listening::scan`
/// reports TCP sockets -- a UDP rule's port is not a listener that section
/// lists, and including it would attach both to whatever TCP listener
/// happens to share that port number.
///
/// One function, called from both places a rule list reaches that section:
/// [`refresh`] below, and the close `PortholeWindow::build` registers.
fn open_tcp_ports(rules: &[WireRule]) -> Vec<u16> {
    rules
        .iter()
        .filter(|r| r.protocol == "tcp")
        .map(|r| r.port)
        .collect()
}

/// Populates "Open now", "Listening" and the status line -- the initial
/// load this crate lacked before this task (see this module's own doc
/// comment), and the same thing a successful open re-runs through
/// [`present_open_dialog`]'s `on_opened` hook.
///
/// The `/proc` scan and the helper round trip run as two **independent**
/// spawned futures below, not sequenced against each other, and either may
/// land first. Nothing here has to be ordered around a "Listening" row's
/// Open button: that button is connected where it is built, by the section
/// that builds it, so calling any of its setters in any order leaves every
/// rendered button working. See `listening_section.rs`'s own doc comment.
///
/// Neither read blocks the UI thread: the D-Bus round trip already yields
/// at every `.await` (the same `glib::spawn_future_local` shape
/// `open_now.rs`'s close button and `open_dialog.rs`'s Open button already
/// use), and the scan, an ordinary blocking file read, runs on GLib's own
/// I/O thread pool via `gio::spawn_blocking`, never on this one. The helper
/// round trip is additionally bounded by [`HELPER_TIMEOUT`] -- see its own
/// doc comment for why an unbounded wait would not be safe here the way it
/// is for a single click's own D-Bus call elsewhere in this crate.
///
/// A failure to reach the helper is not an empty list, and a helper that
/// answered with a typed error is not the same fact as one that never
/// answered at all -- see `open_now.rs`'s and `status_bar.rs`'s own module
/// docs for why conflating either pair is this project's characteristic
/// defect. A `/proc` scan failure is the identical shape one layer down:
/// [`ListeningSection::set_scan_failed`] is that state, not silence plus a
/// stderr line standing in for "nothing is listening" -- and, one layer
/// further down still, `listening_section.rs`'s own `apply` now has to be
/// told a confirmed scan exists at all before it may render that calm page,
/// not merely infer it from an empty list (see its own module doc for the
/// bug that produced).
fn refresh(sections: &Sections) {
    {
        let sections = sections.clone();
        glib::spawn_future_local(async move {
            let scanned =
                gtk::gio::spawn_blocking(|| porthole_core::listening::scan(&RealProcFs)).await;
            match scanned {
                Ok(Ok(services)) => {
                    sections.listening.set_services(&services);
                }
                Ok(Err(e)) => {
                    sections
                        .listening
                        .set_scan_failed(&format!("could not check what is listening: {e}"));
                }
                Err(_) => {
                    sections
                        .listening
                        .set_scan_failed("the listening scan panicked");
                }
            }
        });
    }

    {
        // A third independent read, alongside the `/proc` scan and the
        // helper round trip: reading the address book and resolving every
        // device in it runs subprocesses, so it goes to the same I/O thread
        // pool the scan does and never touches the UI thread. Nothing on
        // screen changes when it lands -- it fills the cache
        // `present_open_dialog` reads when a dialog is actually opened.
        let sections = sections.clone();
        glib::spawn_future_local(async move {
            let loaded = gtk::gio::spawn_blocking(load_devices).await;
            *sections.devices.borrow_mut() = match loaded {
                Ok(snapshot) => snapshot,
                Err(_) => Err("reading the saved devices panicked".to_string()),
            };
        });
    }

    {
        let sections = sections.clone();
        let open_now = sections.open_now.clone();
        let listening = sections.listening.clone();
        let status_bar = sections.status_bar.clone();
        glib::spawn_future_local(async move {
            match with_timeout(fetch_helper_snapshot(), HELPER_TIMEOUT).await {
                Some(Ok(snapshot)) => {
                    match snapshot.rules {
                        Ok(rules) => {
                            let open_ports = open_tcp_ports(&rules);
                            open_now.set_rules(&rules);
                            listening.set_open_ports(&open_ports);
                        }
                        Err(failure) => {
                            apply_failure_to_open_now(&open_now, &failure);
                            listening.set_open_ports_unknown();
                        }
                    }
                    match snapshot.status {
                        Ok(status) => status_bar.set_status(&status),
                        Err(failure) => apply_failure_to_status_bar(&status_bar, &failure),
                    }
                    apply_docker(&sections, snapshot.docker.ok());
                }
                Some(Err(failure)) => {
                    apply_failure_to_open_now(&open_now, &failure);
                    apply_failure_to_status_bar(&status_bar, &failure);
                    listening.set_open_ports_unknown();
                    apply_docker(&sections, None);
                }
                None => {
                    // `with_timeout` won the race: the helper never
                    // answered within `HELPER_TIMEOUT` at all, which is
                    // itself an "unreachable" fact, not an errored reply --
                    // the helper never got the chance to answer at all.
                    let failure = HelperFailure::Unreachable(
                        "could not reach the porthole helper: timed out".to_string(),
                    );
                    apply_failure_to_open_now(&open_now, &failure);
                    apply_failure_to_status_bar(&status_bar, &failure);
                    listening.set_open_ports_unknown();
                    apply_docker(&sections, None);
                }
            }
        });
    }
}

/// Hands one **completed** `docker_ports` outcome to both places that need
/// it: the "Listening" section, which marks the rows it names, and the
/// cache an [`OpenDialog`] opened later reads. `None` is every way that
/// call came back without a list -- no bus, a typed error, the timeout, a
/// `Published` the helper encoded wrongly.
///
/// Only called once a call has actually come back. That is what
/// `ListeningSection::set_docker_unavailable`'s own doc comment requires:
/// calling it before then would put "the porthole helper could not be
/// reached" on screen at every launch, since the `/proc` scan that fills
/// that section's rows lands well before this round trip does.
fn apply_docker(sections: &Sections, published: Option<Vec<Published>>) {
    match published {
        Some(list) => {
            sections.listening.set_docker_ports(&list);
            sections.docker.replace(Some(list));
        }
        None => {
            sections.listening.set_docker_unavailable();
            sections.docker.replace(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure-function coverage of the one piece of this module's own logic
    // that needs no GTK, no D-Bus connection and no async runtime --
    // `classify_failure`'s MethodError-vs-everything-else distinction, the
    // thing I2's fix depends on. Same shape as `open_now.rs`'s own
    // `method_error` fixture, used there to unit-test `helper_message`'s
    // identical verbatim pass-through.
    fn method_error(name: &str, detail: Option<&str>) -> zbus::Error {
        zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from(name.to_string()).unwrap(),
            detail.map(str::to_string),
            zbus::message::Message::method_call("/", "Noop")
                .unwrap()
                .build(&())
                .unwrap(),
        )
    }

    #[test]
    fn a_method_error_is_errored_not_unreachable() {
        // I2: the helper answered here -- a typed error, not silence.
        let e = method_error(
            "com.jacopobriccola.Porthole.NotAuthorized",
            Some("not authorized: com.jacopobriccola.Porthole.List"),
        );
        match classify_failure(e) {
            HelperFailure::Errored(message) => {
                assert_eq!(message, "not authorized: com.jacopobriccola.Porthole.List");
            }
            HelperFailure::Unreachable(message) => {
                panic!("a MethodError must classify as Errored, not Unreachable: {message}")
            }
        }
    }

    #[test]
    fn a_state_failure_classifies_the_same_way_as_a_denial_not_as_unreachable() {
        // I4: `HelperError::State` (a `StateStore` read/write failure) is
        // just as much a `MethodError` as `HelperError::NotAuthorized` is,
        // and `classify_failure` does not -- cannot, from the wire alone --
        // tell them apart. Pinning this is what makes `Errored`'s own doc
        // comment true rather than aspirational: both really do reach the
        // same, deliberately non-refusal-claiming, rendering.
        let e = method_error(
            "com.jacopobriccola.Porthole.State",
            Some("could not read /run/porthole/state.json: permission denied"),
        );
        match classify_failure(e) {
            HelperFailure::Errored(message) => {
                assert_eq!(
                    message,
                    "could not read /run/porthole/state.json: permission denied"
                );
            }
            HelperFailure::Unreachable(message) => {
                panic!("a MethodError must classify as Errored, not Unreachable: {message}")
            }
        }
    }

    #[test]
    fn a_non_method_error_is_unreachable_not_errored() {
        // The connection-lost case: no typed answer came back at all.
        let e = zbus::Error::Failure("the connection was lost".to_string());
        match classify_failure(e) {
            HelperFailure::Unreachable(message) => {
                assert!(
                    message.contains("could not reach the porthole helper"),
                    "{message}"
                );
            }
            HelperFailure::Errored(message) => {
                panic!("a non-MethodError must classify as Unreachable, not Errored: {message}")
            }
        }
    }
}
