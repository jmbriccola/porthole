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
//! [`PortholeWindow::refresh`], and run for the initial load by the task
//! [`PortholeWindow::new`] starts) populates "Open now" and the status line
//! from the helper's own `list`/`status` over D-Bus, and "Listening" from
//! `porthole_core::listening::scan`, and the same function runs again every
//! time [`OpenDialog::on_opened`] fires -- wired onto both the header bar's
//! own "Open a port" button and every "Listening" row's pre-filled one,
//! through `present_open_dialog`.
//!
//! Neither read blocks the UI thread, and the helper round trip is bounded
//! by [`HELPER_TIMEOUT`] (zbus proxies carry no default one of their own).
//! No answer at all, a typed error the helper did answer with, and a
//! confirmed empty list are three different facts and render as three
//! different things -- see `refresh`'s own doc comment, `open_now.rs`'s and
//! `status_bar.rs`'s module docs for why conflating any pair of them is
//! this project's characteristic defect.
//!
//! A fourth joined them once it was measured: an answer this build could not
//! **read**, because the helper is built against a different shape of the
//! same wire type. It used to render as the first -- "could not reach the
//! porthole helper", about a helper that had just replied -- and it is the
//! one of the four that no later refresh can undo. See [`HelperFailure`] and
//! [`stop_talking_to_the_helper`], which is what this window does about it.
//!
//! ## What is open changes without this window doing anything
//!
//! A rule runs out its own clock. Someone runs `porthole close` in a
//! terminal. The machine leaves the subnet a rule was scoped to. The
//! helper's reconciliation sweep finds a record the firewall no longer has.
//! None of those goes through this process, and until this window listened
//! for them it went on showing a list that had stopped being true -- a user
//! on a Fedora Workstation VM watched a row stand for a port their firewall
//! had already stopped holding open.
//!
//! [`listen_and_load`] is the repair: subscribe to the helper's own
//! `RuleOpened`, `RuleClosed` and `NetworkChanged`, and re-read `list` when
//! any of them arrives. What an announcement *carries* is dropped -- see
//! [`subscribe`] for why `list` is the only thing this window ever renders,
//! and [`PortholeWindow::start_listening`] for how the subscription ends.
//! Whose rules those are is unchanged by any of this: `list` is authorized
//! for everyone by polkit and reports every rule porthole holds regardless
//! of who opened it, the announcements are broadcasts carrying the opening
//! uid, and this window filters on neither -- it shows exactly what `list`
//! returns, exactly as it did before.
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
//!
//! That same list is what puts a **Forward** button on the one row shape it
//! can work for, and this file registers what pressing it does:
//! [`OpenDialog::for_forward`], with the port Docker publishes the
//! container on. Registered exactly as the Open button's own callback is,
//! and for the identical reason -- neither section knows what dialog it
//! reaches.
//!
//! ## Writing the address book
//!
//! Until [`present_devices_dialog`] existed, that book could only be read
//! here: a device became a target in the open dialog, and the only way to
//! put one there was a terminal. Two things reach it now -- the main menu's
//! own entry ([`DEVICES_ACTION`]), and the button beside the open dialog's
//! target list, whose slot this file fills. Both present a
//! [`crate::devices_dialog::DevicesDialog`], and both register the hook that
//! re-reads the book after every write, so a device saved while the open
//! dialog is up appears in its target list without it being closed.
//!
//! The helper is not involved in any of it. The address book is
//! client-side, it never crosses the bus, and what does cross it at the
//! moment a port is opened is an already-resolved address.

use std::cell::{Cell, RefCell};
use std::ops::Deref;
use std::rc::Rc;

use adw::prelude::*;
use futures_util::StreamExt;
use gtk::glib;

use porthole_core::command::RealRunner;
use porthole_core::devices;
use porthole_core::docker::Published;
use porthole_core::ipc::{Alignment, PortholeProxy, WireDockerPort, WireRule, WireStatus};
use porthole_core::listening::RealProcFs;

use crate::busy::BusyIndicator;
use crate::devices_dialog::DevicesDialog;
use crate::listening_section::ListeningSection;
use crate::open_dialog::{DeviceEntry, OpenDialog};
use crate::open_now::OpenNowSection;
use crate::status_bar::StatusBar;

/// The saved devices as [`load_devices`] last resolved them, or the reason
/// the address book itself could not be read -- two facts an empty `Vec`
/// alone cannot tell apart, and the second of which must not render as "no
/// devices are saved".
pub type DeviceSnapshot = Result<Vec<DeviceEntry>, String>;

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
    /// The header bar's own "Open a port" button -- held here for one
    /// reason: it is the one control that reaches the helper without going
    /// through a section, and [`stop_talking_to_the_helper`] has to be able
    /// to switch it off.
    open_button: gtk::Button,
    /// Whether a refresh is already scheduled -- see [`schedule_refresh`].
    refresh_pending: Rc<Cell<bool>>,
    /// Whether this window has stopped talking to the helper for good --
    /// see [`stop_talking_to_the_helper`], which is the only thing that sets
    /// it, and which is not reversible from inside this process.
    stopped: Rc<Cell<bool>>,
    /// The header bar's own busy indication, held for as long as a helper
    /// round trip is outstanding -- see [`refresh`], and `busy.rs` for what
    /// it is allowed to mean.
    busy: BusyIndicator,
}

/// The saved-devices entry in the window's own main menu, written the two
/// ways it has to be: the bare name `gio::SimpleAction::new` takes, and the
/// `win.`-prefixed form a `gio::Menu` item points at. Kept adjacent because
/// a menu item naming an action the window does not have renders
/// insensitive and says nothing about why; `tests/devices_dialog.rs` checks
/// that the item and the action actually meet.
const DEVICES_ACTION_NAME: &str = "devices";
const DEVICES_ACTION: &str = "win.devices";

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
    menu_button: gtk::MenuButton,
    devices: Rc<RefCell<DeviceSnapshot>>,
    docker: Rc<RefCell<Option<Vec<Published>>>>,
    refresh_pending: Rc<Cell<bool>>,
    stopped: Rc<Cell<bool>>,
    busy: BusyIndicator,
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
        //
        // That load is now made *inside* the subscription task, after the
        // match rules exist and never conditionally on them -- see
        // [`listen_and_load`] for the ordering and why it is that order.
        window.start_listening();
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

        // The window's main menu, and the one entry it has: the saved
        // devices, reachable without opening a port. The open dialog's own
        // button beside its target list is the other way to the same
        // dialog; this is the way that does not start by choosing a port.
        // A `gio::Menu` item rather than a button, so the same entry is
        // reachable by keyboard through the menu and can grow a second one
        // later without another piece of header chrome.
        let menu = gtk::gio::Menu::new();
        menu.append(Some("Saved Devices"), Some(DEVICES_ACTION));
        let menu_button = gtk::MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .tooltip_text("Main menu")
            .menu_model(&menu)
            .build();
        header_bar.pack_end(&menu_button);

        // Where a refresh says it is still waiting. In the header bar
        // rather than in either section: a refresh is a fact about the
        // window as a whole, and both sections plus the status line are
        // filled from the one round trip it makes. Hidden until
        // `crate::busy::BUSY_DELAY` has gone by, so a refresh that comes
        // straight back shows nothing -- see `busy.rs`.
        let busy = BusyIndicator::new();
        busy.spinner()
            .set_tooltip_text(Some("Waiting for the porthole helper"));
        header_bar.pack_end(busy.spinner());

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
        let refresh_pending: Rc<Cell<bool>> = Rc::new(Cell::new(false));
        let stopped: Rc<Cell<bool>> = Rc::new(Cell::new(false));

        let sections_for_open = Sections {
            window: window.clone(),
            open_now: open_now.clone(),
            listening: listening.clone(),
            status_bar: status_bar.clone(),
            devices: devices.clone(),
            docker: docker.clone(),
            open_button: open_button.clone(),
            refresh_pending: refresh_pending.clone(),
            stopped: stopped.clone(),
            busy: busy.clone(),
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
            open_button: open_button.clone(),
            refresh_pending: refresh_pending.clone(),
            stopped: stopped.clone(),
            busy: busy.clone(),
        };
        listening.connect_open_requested(move |port| {
            present_open_dialog(&sections_for_row, &OpenDialog::for_port(port));
        });

        // And what a "Listening" row's own Forward button does, registered
        // the same way and for the same reason. It carries the port Docker
        // publishes the container on, which is the number
        // `OpenDialog::for_forward` needs and the number `porthole forward`
        // itself takes.
        let sections_for_forward = Sections {
            window: window.clone(),
            open_now: open_now.clone(),
            listening: listening.clone(),
            status_bar: status_bar.clone(),
            devices: devices.clone(),
            docker: docker.clone(),
            open_button: open_button.clone(),
            refresh_pending: refresh_pending.clone(),
            stopped: stopped.clone(),
            busy: busy.clone(),
        };
        listening.connect_forward_requested(move |published_port| {
            present_open_dialog(
                &sections_for_forward,
                &OpenDialog::for_forward(published_port),
            );
        });

        // What the menu entry above actually does. A `gio::SimpleAction` on
        // the window rather than a click handler on a widget: that is what a
        // `gio::Menu` item can point at, and it is the same action whether
        // it is reached with the mouse or from the keyboard.
        let sections_for_devices = Sections {
            window: window.clone(),
            open_now: open_now.clone(),
            listening: listening.clone(),
            status_bar: status_bar.clone(),
            devices: devices.clone(),
            docker: docker.clone(),
            open_button: open_button.clone(),
            refresh_pending: refresh_pending.clone(),
            stopped: stopped.clone(),
            busy: busy.clone(),
        };
        let devices_action = gtk::gio::SimpleAction::new(DEVICES_ACTION_NAME, None);
        devices_action.connect_activate(move |_, _| {
            present_devices_dialog(&sections_for_devices, None);
        });
        window.add_action(&devices_action);

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
            menu_button,
            devices,
            docker,
            refresh_pending,
            stopped,
            busy,
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
            open_button: self.open_button.clone(),
            refresh_pending: self.refresh_pending.clone(),
            stopped: self.stopped.clone(),
            busy: self.busy.clone(),
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

    /// The header bar's main menu, for a test that wants to check it is
    /// reachable from the keyboard and that it really carries an entry --
    /// the entry itself is a `gio::Menu` item, activated through
    /// [`DEVICES_ACTION`] rather than by pressing a widget.
    pub fn menu_button(&self) -> &gtk::MenuButton {
        &self.menu_button
    }

    /// The header bar's own busy indication -- `is_busy()` for "a helper
    /// round trip is outstanding", `is_showing()` for "and it has been
    /// outstanding long enough to say so on screen". A test reads these to
    /// check that a refresh clears them again however it ends: an answer,
    /// a typed error, no helper at all, or [`HELPER_TIMEOUT`] running out.
    pub fn busy(&self) -> &BusyIndicator {
        &self.busy
    }

    /// Every widget this window currently has that a click can activate --
    /// a structural readback, not a hand-maintained list: the header bar's
    /// own "Open a port" button and its main menu, plus every
    /// currently-rendered close button in "Open now" and every
    /// currently-rendered Open **and Forward** button in "Listening" (rows
    /// with none of them -- a "Listening" row that can be neither opened nor
    /// forwarded, an unopened "Open now" list -- contribute nothing, since
    /// there is nothing there to reach).
    /// `tests/window.rs`'s own keyboard-reachability test checks
    /// `is_focusable()` on each of these: a GNOME app that needs a mouse is
    /// not a GNOME app.
    ///
    /// `gtk::Widget`, not `gtk::Button`: the main menu is a
    /// `gtk::MenuButton`, and a list that could only hold buttons would
    /// have left it out while still claiming to be every one of them.
    pub fn actionable_widgets(&self) -> Vec<gtk::Widget> {
        let mut widgets: Vec<gtk::Widget> = vec![
            self.open_button.clone().upcast(),
            self.menu_button.clone().upcast(),
        ];
        for index in 0..self.open_now.rows().len() {
            if let Some(button) = self.open_now.close_button_for(index) {
                widgets.push(button.upcast());
            }
        }
        for index in 0..self.listening.rows().len() {
            if let Some(button) = self.listening.open_button_for(index) {
                widgets.push(button.upcast());
            }
            if let Some(button) = self.listening.forward_button_for(index) {
                widgets.push(button.upcast());
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

    /// Starts the one task that keeps this window's view of what is open
    /// tied to the helper's, and arranges for it to end.
    ///
    /// **How it ends.** Two things here hold this window: the task, and the
    /// expiry callback left on the "Open now" section. The window's own
    /// `close-request` releases both, and nothing else holds either. Every
    /// window `app::build`'s activation handler makes gets its own
    /// subscription, and closing one ends that one.
    ///
    /// Removing the task's source from the main context drops the future,
    /// the signal streams and the D-Bus connection under them -- so the
    /// match rules go too. `slot` holds the source's id and nothing else, a
    /// plain integer, so the handler hanging off the window is not a second
    /// reference back into the task; whichever of the two empties it first
    /// -- the task on its way out, the handler on its way in -- leaves
    /// nothing for the other, because `SourceId::remove` on a source that
    /// has already finished is a panic, not a no-op.
    ///
    /// The callback is the cut described on
    /// [`OpenNowSection::forget_expiry_unconfirmed`]: that section outlives
    /// every window in this process, and the callback registered below holds
    /// this one.
    ///
    /// **`close-request`, not `destroy`.** Measured in this milestone's own
    /// container, on a real presented window: `gtk::Window::destroy` hid the
    /// window and emitted no `destroy` signal at all, so a handler on that
    /// signal never ran. GTK4 emits it from the widget's own dispose, which
    /// needs every reference to have gone -- and this crate holds one that
    /// does not, the `Sections` inside `ListeningSection`'s own
    /// `connect_open_requested` callback, which points back at the window
    /// that holds the section. `close-request` is the signal the window
    /// manager's close button, `Ctrl-W` and `gtk::Window::close` all raise,
    /// and it fires with references outstanding.
    fn start_listening(&self) {
        // The other half of the same problem, one section down: a countdown
        // reaching zero is a deadline, not an outcome, and only `list` can
        // settle what happened -- which "Open now" never calls. It reports
        // the deadline; this is what reads.
        let sections_for_expiry = self.sections();
        self.open_now.connect_expiry_unconfirmed(move || {
            schedule_refresh(&sections_for_expiry);
        });

        let slot: Rc<RefCell<Option<glib::SourceId>>> = Rc::new(RefCell::new(None));
        let sections = self.sections();
        let slot_for_task = slot.clone();
        let handle = glib::spawn_future_local(async move {
            listen_and_load(sections).await;
            slot_for_task.borrow_mut().take();
        });
        // The task cannot have run yet: it only runs when the main context
        // iterates, and this is still inside the constructor.
        *slot.borrow_mut() = handle.into_source_id().ok();
        let open_now = self.open_now.clone();
        self.window.connect_close_request(move |_| {
            if let Some(id) = slot.borrow_mut().take() {
                id.remove();
            }
            open_now.forget_expiry_unconfirmed();
            // Nothing here is a reason to keep the window: this is
            // bookkeeping on the way out, not a veto.
            glib::Propagation::Proceed
        });
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
/// A third fact joined the two above once it was measured, and the two could
/// not hold it: the helper answered, and **this build could not read the
/// answer**. `porthole_core::ipc::is_undecodable` is what recognises it, and
/// its own doc comment is where the measurement lives. It arrives as
/// `zbus::Error::Variant`, which is not a `MethodError` -- so before this
/// existed it fell straight through to `Unreachable`, and this window told
/// the user "could not reach the porthole helper" about a helper that had
/// just replied. That is the same false claim `status_bar.rs`'s own module
/// doc calls this project's characteristic defect, made about the one case
/// where the truth is neither of the other two.
///
/// It is also the only one of the three that does not go away by itself:
/// `Unreachable` and `Errored` can both be true now and false at the next
/// refresh, and this cannot -- the next answer is built by the same two
/// binaries and is equally unreadable. That is why it is the only one that
/// stops the window asking; see [`stop_talking_to_the_helper`].
enum HelperFailure {
    Unreachable(String),
    Errored(String),
    Undecodable(String),
}

fn classify_failure(e: zbus::Error) -> HelperFailure {
    // Asked first: a decode failure is not a `MethodError`, so the order
    // below does not actually matter today -- it is written this way so that
    // it would still not matter if it ever did.
    if porthole_core::ipc::is_undecodable(&e) {
        return HelperFailure::Undecodable(format!(
            "porthole could not read the porthole helper's answer: {e}"
        ));
    }
    if nobody_answered(&e) {
        // A `MethodError` by shape and not an answer by nature: the bus
        // sends this when the process that was going to reply went away
        // before it did, with the detail `Remote peer disconnected`. Reading
        // it as `Errored` put that phrase on screen under "Porthole helper
        // reported an error", as though it were the helper's own account of
        // something -- a sentence no part of porthole ever wrote, about a
        // helper that reported nothing at all.
        //
        // Every call this window makes now asks again once on it (see
        // `porthole_core::ipc::once_more_if_worth_asking_again`), so
        // reaching here means two calls in a row found nobody. That is a
        // helper that is genuinely not answering, which is what
        // `Unreachable` says.
        return HelperFailure::Unreachable(format!(
            "could not reach the porthole helper: nothing answered ({e})"
        ));
    }
    match &e {
        zbus::Error::MethodError(..) => HelperFailure::Errored(helper_message(&e)),
        _ => HelperFailure::Unreachable(format!("could not reach the porthole helper: {e}")),
    }
}

/// Whether this is the bus reporting that nobody answered, rather than
/// anything the helper said -- [`porthole_core::ipc::NO_REPLY_ERROR`], which
/// is where that name is spelled and where what it means is written down.
///
/// Deliberately *not* `porthole_core::ipc::worth_asking_again`, which covers
/// this name and one more. The other one, `Retiring`, is a sentence the
/// helper composed for a person and which names its own remedy, so it goes
/// on being rendered as what it is: the helper answering. This is the one
/// that is a `MethodError` in shape and an absence of one in fact.
fn nobody_answered(e: &zbus::Error) -> bool {
    matches!(
        e,
        zbus::Error::MethodError(name, ..)
            if name.as_str() == porthole_core::ipc::NO_REPLY_ERROR
    )
}

/// The two below are reached only for a failure that is **not**
/// `Undecodable`: every path that can produce one routes it to
/// [`stop_talking_to_the_helper`] first, which is where the window's answer
/// to it lives. The arms are here because the enum has three variants and a
/// wildcard would silently absorb a fourth; they pass `None` for the
/// alignment because nothing on these paths has asked the helper for its
/// version.
fn apply_failure_to_open_now(open_now: &OpenNowSection, failure: &HelperFailure) {
    match failure {
        HelperFailure::Unreachable(message) => open_now.set_unreachable(message),
        HelperFailure::Errored(message) => open_now.set_errored(message),
        HelperFailure::Undecodable(message) => open_now.set_undecodable(message),
    }
}

fn apply_failure_to_status_bar(status_bar: &StatusBar, failure: &HelperFailure) {
    match failure {
        HelperFailure::Unreachable(message) => status_bar.set_unreachable(message),
        HelperFailure::Errored(message) => status_bar.set_errored(message),
        HelperFailure::Undecodable(message) => status_bar.set_undecodable(message, None),
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
    /// Which of the two binaries is the older half, as the helper's own
    /// `ProtocolVersion` answered -- and **only** when one of the three
    /// results above could not be read at all, which is the one situation
    /// the answer changes anything in. `None` everywhere else, and also for
    /// a version this build could not read either: nothing is guessed from
    /// silence.
    ///
    /// Read over the same connection the three calls above used, through
    /// `porthole_core::ipc::read_protocol_version`, which builds a proxy for
    /// the one call -- never a cached property, for the reason measured in
    /// that function's own doc comment.
    alignment: Option<Alignment>,
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
    // Each of the three asks again once when the first attempt was one to
    // ask again about rather than to report -- a helper between lives, which
    // since the idle exit is a routine event on an idle machine rather than
    // a rare one. Independently, for the same reason the three results are
    // independent: whichever of them arrives during a retirement is the one
    // that has to be asked twice, and the fresh instance the first retry
    // activates is already serving by the time the next call goes out.
    //
    // Nothing new appears on screen while it happens. A refresh already holds
    // the header bar's busy indication across the whole round trip (see
    // `busy.rs`), so a retry is simply that wait, one bus activation longer
    // -- measured at 22-31 ms warm and ~250 ms cold, against the eight
    // seconds `HELPER_TIMEOUT` allows.
    let rules = porthole_core::ipc::once_more_if_worth_asking_again(|| proxy.list())
        .await
        .map_err(classify_failure);
    let status = porthole_core::ipc::once_more_if_worth_asking_again(|| proxy.status())
        .await
        .map_err(classify_failure);
    // A third independent result, for the same reason `rules` and `status`
    // are two: a `docker_ports` failure must not throw away a `list` that
    // already succeeded.
    let docker =
        match porthole_core::ipc::once_more_if_worth_asking_again(|| proxy.docker_ports()).await {
            Ok(wire) => wire
                .iter()
                .map(published_from_wire)
                .collect::<Result<Vec<_>, String>>()
                .map_err(HelperFailure::Errored),
            Err(e) => Err(classify_failure(e)),
        };
    let mut snapshot = HelperSnapshot {
        rules,
        status,
        docker,
        alignment: None,
    };
    // One more round trip, and only on the one path where the answer is
    // worth anything: an answer this build could not read is the failure
    // that does not go away by itself, and which half is old is what the
    // window has to tell the person in front of it. Every other refresh
    // pays nothing for this.
    if first_undecodable(&snapshot).is_some() {
        snapshot.alignment = porthole_core::ipc::once_more_if_worth_asking_again(|| {
            porthole_core::ipc::read_protocol_version(&connection)
        })
        .await
        .ok()
        .map(porthole_core::ipc::alignment);
    }
    Ok(snapshot)
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
pub fn load_devices() -> DeviceSnapshot {
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
/// `loading_note`) forever, rather than ever settling into a state a user
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

/// One refresh per burst of announcements.
///
/// `close --all` announces every rule it closed, one signal each, and a
/// refresh is three D-Bus calls, a `/proc` scan and a subprocess per saved
/// device. The first announcement schedules a refresh this far ahead; the
/// rest arrive inside that window and are absorbed by it.
const SIGNAL_COALESCE: std::time::Duration = std::time::Duration::from_millis(200);

/// Asks for a [`refresh`] shortly, unless one is already asked for.
///
/// The flag is cleared before the refresh runs, so an announcement that
/// arrives while that refresh is in flight schedules the next one rather
/// than being dropped into it.
fn schedule_refresh(sections: &Sections) {
    if sections.stopped.get() {
        return;
    }
    if sections.refresh_pending.replace(true) {
        return;
    }
    let sections = sections.clone();
    glib::timeout_add_local_once(SIGNAL_COALESCE, move || {
        sections.refresh_pending.set(false);
        refresh(&sections);
    });
}

/// Every announcement the helper makes, as one stream of "read `list`
/// again", together with the connection and proxy they arrive over -- both
/// returned so the caller's own frame keeps them alive for as long as the
/// stream is read.
///
/// `None` is every way there was nothing to subscribe to: no bus, no
/// activatable helper, a connection lost while the match rules were being
/// installed.
///
/// **The payloads are dropped here.** `RuleOpened` carries the rule the
/// helper created and `RuleClosed` carries the rule and why it stopped being
/// open, and this window renders neither. `porthole_core::ipc`'s own
/// `rule_closed` doc gives three reasons a subscriber cannot keep its view
/// from these alone: `close --id --forget` drops a record with nothing
/// announced at all, announcements are emitted after the state lock is
/// released so one can arrive ahead of the `RuleOpened` for a different
/// rule, and anything sent before the match rules existed is simply gone.
/// So `list` is the authority here in the strongest sense available -- it is
/// the only thing this window ever renders, and an announcement is a cue to
/// read it. There is no second account of what is open for the list to
/// disagree with.
async fn subscribe() -> Option<(
    zbus::Connection,
    PortholeProxy<'static>,
    futures_util::stream::LocalBoxStream<'static, ()>,
)> {
    let connection = zbus::Connection::system().await.ok()?;
    let proxy = PortholeProxy::new(&connection).await.ok()?;
    let opened = proxy.receive_rule_opened().await.ok()?;
    let closed = proxy.receive_rule_closed().await.ok()?;
    // The machine's own subnet changing is not itself a rule leaving the
    // list, but it is what the helper closes subnet-scoped rules for, and
    // it changes the network the status line reports either way.
    let network = proxy.receive_network_changed().await.ok()?;
    let signals = futures_util::stream::select_all(vec![
        opened.map(|_| ()).boxed_local(),
        closed.map(|_| ()).boxed_local(),
        network.map(|_| ()).boxed_local(),
    ])
    .boxed_local();
    Some((connection, proxy, signals))
}

/// Subscribes, then loads, then keeps loading whenever the helper says
/// something changed.
///
/// **Subscribe first, then call.** The helper is D-Bus activated, so the
/// call that reaches it is what starts it, and its start-up sweep announces
/// what it dropped as soon as it owns the bus name. A client whose match
/// rules already exist by then receives those; one that calls first can lose
/// them. `porthole-agent`'s own `main` does this in the same order, for the
/// same reason, and says so at greater length.
///
/// The load runs whether or not subscribing worked. A window that could not
/// subscribe still has to populate, and a helper that is not there is a
/// state both sections and the status line already render as itself.
async fn listen_and_load(sections: Sections) {
    let subscription = subscribe().await;
    refresh(&sections);
    let Some((_connection, _proxy, mut signals)) = subscription else {
        return;
    };
    while signals.next().await.is_some() {
        schedule_refresh(&sections);
    }
    // The stream ends when the connection under it does. One more read
    // replaces what is on screen with whatever the next call finds, rather
    // than leaving the last answer standing with nothing left that could
    // ever change it.
    refresh(&sections);
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

    // What the button beside the target list does. Registered here, and not
    // in `open_dialog.rs`, for the reason every other cross-section callback
    // in this file is: that dialog knows nothing about the saved-devices one.
    let sections_for_devices = sections.clone();
    let dialog_for_devices = dialog.clone();
    dialog.on_manage_devices(move || {
        present_devices_dialog(&sections_for_devices, Some(dialog_for_devices.clone()));
    });

    dialog.present(Some(&sections.window));
}

/// Re-reads the address book, off the UI thread, into the cache
/// [`present_open_dialog`] hands to every dialog it opens -- and, when one
/// is currently on screen, straight into that one as well.
///
/// Two callers, one function: [`refresh`] runs it as a third read alongside
/// the `/proc` scan and the helper round trip, and
/// [`present_devices_dialog`] runs it again after every write to the book,
/// so a device saved while the open dialog is up appears in its target list
/// without the dialog being closed and re-opened.
///
/// Reading the book resolves every device in it, and each resolution runs a
/// subprocess, so this goes to GLib's own I/O thread pool. Nothing on screen
/// changes when a `None` call lands: it fills a cache.
fn reload_devices(sections: &Sections, dialog: Option<OpenDialog>) {
    let sections = sections.clone();
    glib::spawn_future_local(async move {
        let loaded = gtk::gio::spawn_blocking(load_devices).await;
        let snapshot = match loaded {
            Ok(snapshot) => snapshot,
            Err(_) => Err("reading the saved devices panicked".to_string()),
        };
        if let Some(dialog) = &dialog {
            match &snapshot {
                Ok(entries) => dialog.set_devices(entries),
                Err(reason) => dialog.set_devices_unreadable(reason),
            }
        }
        *sections.devices.borrow_mut() = snapshot;
    });
}

/// Presents a fresh [`DevicesDialog`] -- from the main menu, where
/// `open_dialog` is `None`, and from the open dialog's own button beside its
/// target list, where it is the dialog that button was pressed in.
///
/// Registered on it: a hook that re-reads the address book after every write
/// and pushes the result back into that same open dialog, when there is one.
/// This is the only place that knows about both dialogs at once, exactly as
/// it is the only place that knows about more than one section.
///
/// Nothing here goes near the helper. The address book is client-side and the
/// helper never learns that devices exist -- see
/// `porthole_core::devices`'s own module doc for what that keeps small.
fn present_devices_dialog(sections: &Sections, open_dialog: Option<OpenDialog>) {
    let dialog = DevicesDialog::new();

    let sections_for_changed = sections.clone();
    let open_dialog_for_changed = open_dialog.clone();
    dialog.on_changed(move || {
        reload_devices(&sections_for_changed, open_dialog_for_changed.clone());
    });

    // The book and the neighbour table are read here rather than in the
    // constructor, so a test can build one of these and drive it with
    // fixture data -- the same split `PortholeWindow::new_without_initial_load`
    // exists for.
    dialog.reload();

    // Over the dialog that asked for it, when one did; over the window
    // otherwise.
    match &open_dialog {
        Some(open) => dialog.present(Some(open.dialog())),
        None => dialog.present(Some(&sections.window)),
    }
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
    // Nothing after a helper this window cannot read -- see
    // [`stop_talking_to_the_helper`]. Every read below would come back in
    // the same unreadable shape, and the two that do not touch the helper
    // (the `/proc` scan and the address book) would keep repainting rows
    // under a banner saying this window has stopped asking.
    if sections.stopped.get() {
        return;
    }
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

    // A third independent read, alongside the `/proc` scan and the helper
    // round trip -- see [`reload_devices`], which a write to the address
    // book runs again on its own.
    reload_devices(sections, None);

    {
        let sections = sections.clone();
        let open_now = sections.open_now.clone();
        let listening = sections.listening.clone();
        let status_bar = sections.status_bar.clone();
        let busy = sections.busy.clone();
        glib::spawn_future_local(async move {
            // The one read here that can take long enough to look like a
            // stall. The `/proc` scan and the address book above are on
            // GLib's I/O thread pool and come back in milliseconds; this
            // one crosses a bus, and the helper behind it can be slow or
            // absent. Held across the round trip and dropped on the way
            // out of this block, whichever way that is -- see `busy.rs`.
            let _busy = busy.begin();
            match with_timeout(fetch_helper_snapshot(), HELPER_TIMEOUT).await {
                Some(Ok(snapshot)) => {
                    // Before anything is rendered from this snapshot: one
                    // unreadable answer settles the whole window, and the
                    // other two calls' results are about the same two
                    // binaries. See [`stop_talking_to_the_helper`].
                    if let Some(message) = first_undecodable(&snapshot) {
                        stop_talking_to_the_helper(&sections, &message, snapshot.alignment);
                        return;
                    }
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
                    // The one case where no call was even attempted -- a
                    // connection or a proxy that could not be made. It can
                    // carry `Undecodable` too, in principle, and is routed
                    // the same way rather than rendered and then forgotten.
                    if let HelperFailure::Undecodable(message) = &failure {
                        // `None`: no connection was made at all here, so
                        // there was nothing to ask which half is older.
                        stop_talking_to_the_helper(&sections, message, None);
                        return;
                    }
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

/// The first of one refresh's three answers this build could not read, if
/// any -- all three, because `list`, `status` and `docker_ports` are three
/// independent results (see [`HelperSnapshot`]) and any of them can be the
/// one carrying a type that changed. `WireStatus` embeds the same
/// `WireRule`, so in the measured case `list` and `status` fail together and
/// `docker_ports` does not; nothing here depends on that staying true.
fn first_undecodable(snapshot: &HelperSnapshot) -> Option<String> {
    [
        snapshot.rules.as_ref().err(),
        snapshot.status.as_ref().err(),
        snapshot.docker.as_ref().err(),
    ]
    .into_iter()
    .flatten()
    .find_map(|failure| match failure {
        HelperFailure::Undecodable(message) => Some(message.clone()),
        _ => None,
    })
}

/// Say that this window and the helper are built against different shapes of
/// the same wire type, and stop the window doing anything that would reach
/// the helper again.
///
/// **Why not simply exit, the way `porthole-agent` does.** A window is
/// something a person is looking at and has arranged on a screen; one that
/// vanishes under their hands has reported nothing. The choice recorded for
/// this case (`docs/superpowers/specs/2026-09-09-update-notifier-design.md`:
/// *«La GUI aperta non può ri-eseguirsi mentre è in uso. Se ne accorge e lo
/// dice»*) is that it notices and says so, rather than going on talking to a
/// helper it was not built for. So the window and everything in it stay
/// exactly where they were, readable, and what changes is that it stops
/// asking and stops offering.
///
/// **Why the buttons go insensitive, and not merely the refresh.** This is
/// the half that is not cosmetic. A stale window's `open` sends `(qssu)` and
/// a current helper's `open` still takes `(qssu)`, so the request goes
/// through and **the port really opens** -- it is the reply this window
/// cannot read. Leaving the buttons live would let a person press Open, be
/// told it failed, and have a hole in their firewall anyway. Every button
/// that reaches the helper is behind one of the two widgets switched off
/// here, and sensitivity is inherited in GTK, so a "Listening" row rebuilt
/// after this point by an in-flight `/proc` scan is unpressable too.
///
/// The saved-devices menu stays live on purpose: the address book is
/// client-side and never crosses the bus (see this module's own doc
/// comment), so it is the one thing here that still works.
///
/// Not reversible. Nothing this process can do makes the two binaries
/// agree, and a window that quietly came back to life would be claiming
/// something happened that it cannot have observed.
fn stop_talking_to_the_helper(sections: &Sections, message: &str, alignment: Option<Alignment>) {
    if sections.stopped.replace(true) {
        return;
    }
    sections.open_now.set_undecodable(message);
    sections.status_bar.set_undecodable(message, alignment);
    // The rule list is gone, so "already open" is no longer known -- the
    // same call every other failed refresh makes.
    sections.listening.set_open_ports_unknown();
    // The Docker state is deliberately left as it was. Whatever a previous
    // refresh confirmed about Docker is no less true than the `/proc` rows
    // beside it, and `set_docker_unavailable`'s own note says the helper
    // "could not be reached, or answered with an error", which is the one
    // thing that did not happen here.
    sections.listening.widget().set_sensitive(false);
    sections.open_button.set_sensitive(false);
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
    fn nobody_answering_is_unreachable_even_though_it_arrives_as_a_method_error() {
        // The bus sends this when the process that was going to reply went
        // away before it did -- a helper killed by an upgrade, or the last
        // instant of one retiring. It is a `MethodError` in shape and an
        // absence of an answer in fact, and reading it as `Errored` put
        // `Remote peer disconnected` on screen under "Porthole helper
        // reported an error", as though it were the helper's own account of
        // something. No part of porthole ever wrote that sentence.
        //
        // Every call this window makes now asks again once on it, so getting
        // here means two calls in a row found nobody -- which is a helper
        // that is genuinely not answering.
        let e = method_error(
            porthole_core::ipc::NO_REPLY_ERROR,
            Some("Remote peer disconnected"),
        );
        match classify_failure(e) {
            HelperFailure::Unreachable(message) => {
                assert!(message.contains("could not reach"), "{message}");
                assert!(
                    message.contains("nothing answered"),
                    "and what happened was that nobody replied: {message}"
                );
            }
            HelperFailure::Errored(message) => {
                panic!("nothing answered; the helper reported nothing: {message}")
            }
            HelperFailure::Undecodable(message) => {
                panic!("there was no answer here to fail to read: {message}")
            }
        }

        // The negative control, and the reason this is not simply
        // `worth_asking_again`: `Retiring` is the *other* name a client asks
        // again on, and it is a sentence the helper composed for a person
        // which names its own remedy. A second refusal is still the helper
        // answering, and must go on being rendered as one.
        let retiring = method_error(
            porthole_core::ipc::RETIRING_ERROR,
            Some(
                "the porthole helper was retiring when this request arrived and did not \
                  act on it: ask again",
            ),
        );
        match classify_failure(retiring) {
            HelperFailure::Errored(message) => assert!(message.contains("ask again"), "{message}"),
            HelperFailure::Unreachable(message) => {
                panic!("the helper answered this one, in its own words: {message}")
            }
            HelperFailure::Undecodable(message) => panic!("{message}"),
        }
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
            HelperFailure::Undecodable(message) => {
                panic!("this answer was read successfully; it just said no: {message}")
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
            HelperFailure::Undecodable(message) => {
                panic!("this answer was read successfully; it just said no: {message}")
            }
        }
    }

    #[test]
    fn an_answer_this_build_cannot_read_is_neither_unreachable_nor_errored() {
        // The measured case, built by zbus's own decoder rather than by
        // hand: a `list` answered in the shape from before the forward
        // feature. Before this classification existed it landed in
        // `Unreachable` -- a `SignatureMismatch` is not a `MethodError` --
        // and this window said "could not reach the porthole helper" about a
        // helper that had just answered.
        #[derive(serde::Serialize, zbus::zvariant::Type)]
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
        let old = vec![RuleBeforeForward {
            id: "abc".to_string(),
            port: 5173,
            protocol: "tcp".to_string(),
            target: "10.10.10.0/24".to_string(),
            scope: "network".to_string(),
            backend: "firewalld".to_string(),
            opened_at: 1_757_000_000,
            expires_at: 1_757_003_600,
            uid: 1000,
        }];
        let e = zbus::message::Message::signal("/", "com.jacopobriccola.Porthole1", "Listed")
            .unwrap()
            .build(&(old,))
            .unwrap()
            .body()
            .deserialize::<(Vec<WireRule>,)>()
            .expect_err("the two list signatures disagree");

        match classify_failure(e) {
            HelperFailure::Undecodable(message) => {
                assert!(
                    !message.contains("could not reach"),
                    "the helper answered: {message}"
                );
                assert!(
                    message.contains("could not read"),
                    "and what failed was reading it: {message}"
                );
            }
            HelperFailure::Unreachable(message) => {
                panic!("the helper answered; this is not unreachable: {message}")
            }
            HelperFailure::Errored(message) => {
                panic!("the helper reported no error; this window could not read it: {message}")
            }
        }
    }

    #[test]
    fn one_unreadable_answer_out_of_three_is_enough_to_settle_the_window() {
        // `list`, `status` and `docker_ports` are three independent results
        // on purpose, so that one failing does not throw away another that
        // succeeded -- but this particular failure is not about one call, it
        // is about the two binaries, so any one of the three carrying it is
        // what the window acts on. Each position checked, so a future
        // rewrite that only looks at `rules` fails here.
        let unreadable = || HelperFailure::Undecodable("cannot read this".to_string());
        let ordinary = || HelperFailure::Errored("not authorized".to_string());

        for position in 0..3 {
            let snapshot = HelperSnapshot {
                rules: if position == 0 {
                    Err(unreadable())
                } else {
                    Err(ordinary())
                },
                status: if position == 1 {
                    Err(unreadable())
                } else {
                    Err(ordinary())
                },
                docker: if position == 2 {
                    Err(unreadable())
                } else {
                    Err(ordinary())
                },
                // Not read on this path: `first_undecodable` is what
                // decides whether it is worth asking for at all.
                alignment: None,
            };
            assert_eq!(
                first_undecodable(&snapshot).as_deref(),
                Some("cannot read this"),
                "position {position}"
            );
        }

        // And the negative control: three ordinary failures are not this
        // case, and must go on rendering as themselves.
        let ordinary_only = HelperSnapshot {
            rules: Err(ordinary()),
            status: Err(HelperFailure::Unreachable("no bus".to_string())),
            docker: Err(ordinary()),
            alignment: None,
        };
        assert_eq!(first_undecodable(&ordinary_only), None);
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
            HelperFailure::Undecodable(message) => {
                panic!("nothing came back to be read here at all: {message}")
            }
        }
    }
}
