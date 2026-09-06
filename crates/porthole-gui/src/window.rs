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
//! Neither read blocks the UI thread, and a failure to reach the helper is
//! not rendered as an empty list -- see `refresh`'s own doc comment,
//! `open_now.rs`'s and `status_bar.rs`'s module docs for why conflating
//! those two facts is this project's characteristic defect.

use std::ops::Deref;

use adw::prelude::*;
use gtk::glib;

use porthole_core::ipc::{PortholeProxy, WireRule, WireStatus};
use porthole_core::listening::RealProcFs;

use crate::listening_section::ListeningSection;
use crate::open_dialog::OpenDialog;
use crate::open_now::OpenNowSection;
use crate::status_bar::StatusBar;

/// The width, in CSS pixels, at or below which the narrow layout applies.
/// Tasks 3-6 attach the actual layout changes to this same `Breakpoint`
/// object, reachable via [`PortholeWindow::breakpoint`], through
/// `Breakpoint::add_setter`; this task only establishes that a real
/// breakpoint exists, is registered on a real window, and genuinely applies
/// once that window is narrow.
const NARROW_WIDTH_PX: f64 = 400.0;

pub struct PortholeWindow {
    window: adw::ApplicationWindow,
    content: gtk::Box,
    breakpoint: adw::Breakpoint,
    toast_overlay: adw::ToastOverlay,
    open_now: OpenNowSection,
    listening: ListeningSection,
    status_bar: StatusBar,
    open_button: gtk::Button,
}

impl Deref for PortholeWindow {
    type Target = adw::ApplicationWindow;

    fn deref(&self) -> &Self::Target {
        &self.window
    }
}

impl PortholeWindow {
    pub fn new(app: &adw::Application) -> Self {
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

        let window_for_open = window.clone();
        let open_now_for_open = open_now.clone();
        let listening_for_open = listening.clone();
        let status_bar_for_open = status_bar.clone();
        open_button.connect_clicked(move |_| {
            present_open_dialog(
                &window_for_open,
                &OpenDialog::new(),
                &open_now_for_open,
                &listening_for_open,
                &status_bar_for_open,
            );
        });

        // The initial load this constructor owes -- see this module's own
        // doc comment on the planning defect this task repairs. Both
        // sections start out showing their own calm "nothing yet" state
        // (built into `OpenNowSection`/`ListeningSection` themselves) for
        // the brief span before this resolves; `refresh` runs the same
        // path a later explicit refresh does, there is no separate
        // "first load" code.
        refresh(&window, &open_now, &listening, &status_bar);

        Self {
            window,
            content,
            breakpoint,
            toast_overlay,
            open_now,
            listening,
            status_bar,
            open_button,
        }
    }

    /// The box Tasks 3-6 append their sections into, one per task.
    pub fn content(&self) -> &gtk::Box {
        &self.content
    }

    /// The narrow-width breakpoint registered on this window, for a later
    /// task to attach layout changes to via `Breakpoint::add_setter`.
    ///
    /// This is the same object `current_breakpoint()` (from
    /// `AdwApplicationWindowExt`, reachable via `Deref`) reports back once
    /// the window is actually narrow -- see `tests/window.rs` for a test
    /// that resizes a real window and checks exactly that.
    pub fn breakpoint(&self) -> &adw::Breakpoint {
        &self.breakpoint
    }

    /// Whether the breakpoint this window registered would apply once the
    /// window has narrowed to `px` -- reads the real, live
    /// `BreakpointCondition`'s own string form back from the GObject
    /// (`adw_breakpoint_condition_to_string`), rather than repeating the
    /// `NARROW_WIDTH_PX` constant that built it, so a future edit that
    /// changed the registered breakpoint without changing that constant
    /// would still be caught here.
    ///
    /// `tests/window.rs`'s own `the_window_is_usable_at_a_narrow_width` is
    /// the stronger, end-to-end version of this same property: a real
    /// window, really laid out, really narrow. This accessor answers the
    /// same question without presenting a window at all, and -- unlike
    /// resizing a real, already-presented window (see this module's own
    /// doc comment on why that is unreliable) -- can be asked more than
    /// once.
    pub fn has_breakpoint_below(&self, px: f64) -> bool {
        self.breakpoint
            .condition()
            .and_then(|c| max_width_px(&c.to_str()))
            .is_some_and(|threshold| threshold >= px)
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
        refresh(
            &self.window,
            &self.open_now,
            &self.listening,
            &self.status_bar,
        );
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

/// Everything one refresh needs from the helper, fetched over a single
/// D-Bus connection: every rule `list` currently reports, and the
/// backend's own `status`.
struct HelperSnapshot {
    rules: Vec<WireRule>,
    status: WireStatus,
}

/// A connection/proxy-construction failure and a call that reached the
/// helper but was refused (a polkit denial, say -- `list` and `status`
/// both go through the same authorization check `open`/`close` do, see
/// `porthole-helper/src/service.rs`) are different facts, and this keeps
/// them apart the same way `open_now.rs`'s `close_by_id_over_dbus` and
/// `open_dialog.rs`'s `open_over_dbus` already do: the former gets the
/// "could not reach the helper" wrapper every other D-Bus call in this
/// crate uses for that exact failure; the latter gets the helper's own
/// message, verbatim, through `helper_message`. Reformatting a polkit
/// denial as "could not reach the helper" would itself be the two-facts-
/// into-one collapse this milestone keeps finding.
async fn fetch_helper_snapshot() -> Result<HelperSnapshot, String> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|e| format!("could not reach the porthole helper: {e}"))?;
    let proxy = PortholeProxy::new(&connection)
        .await
        .map_err(|e| format!("could not reach the porthole helper: {e}"))?;
    let rules = proxy.list().await.map_err(|e| helper_message(&e))?;
    let status = proxy.status().await.map_err(|e| helper_message(&e))?;
    Ok(HelperSnapshot { rules, status })
}

/// Presents `dialog`, transient for `window`, and registers its
/// `on_opened` hook -- task 5's own hook, left uncalled until this task,
/// see this module's own doc comment -- to run [`refresh`] again on a
/// successful open. Shared by the header bar's own "Open a port" button
/// and every "Listening" row's pre-filled one (wired by
/// `wire_listening_open_buttons`), so both paths refresh the same way.
fn present_open_dialog(
    window: &adw::ApplicationWindow,
    dialog: &OpenDialog,
    open_now: &OpenNowSection,
    listening: &ListeningSection,
    status_bar: &StatusBar,
) {
    let window_for_refresh = window.clone();
    let open_now = open_now.clone();
    let listening = listening.clone();
    let status_bar = status_bar.clone();
    dialog.on_opened(move |_rule| {
        refresh(&window_for_refresh, &open_now, &listening, &status_bar);
    });
    dialog.present(Some(window));
}

/// Connects each "Listening" row's own Open button (if it has one -- see
/// `listening_section.rs`'s own doc comment for which rows do not) to a
/// dialog pre-filled with that row's port.
///
/// Every `set_services`/`set_open_ports` call rebuilds every row from
/// scratch (`listening_section.rs`'s own `apply`), which drops whatever
/// click handler a previous call to this function had connected -- so this
/// has to run again after each refresh, which is exactly what `refresh`
/// does, once, after both of `listening`'s setters have already run for
/// that refresh. It lives here rather than inside `listening_section.rs`
/// itself because that module renders what it is given and knows nothing
/// about `OpenDialog` or this window.
fn wire_listening_open_buttons(
    window: &adw::ApplicationWindow,
    open_now: &OpenNowSection,
    listening: &ListeningSection,
    status_bar: &StatusBar,
) {
    for index in 0..listening.rows().len() {
        let (Some(button), Some(port)) = (
            listening.open_button_for(index),
            listening.activate_open(index),
        ) else {
            continue;
        };
        let window = window.clone();
        let open_now = open_now.clone();
        let listening = listening.clone();
        let status_bar = status_bar.clone();
        button.connect_clicked(move |_| {
            present_open_dialog(
                &window,
                &OpenDialog::for_port(port),
                &open_now,
                &listening,
                &status_bar,
            );
        });
    }
}

/// Populates "Open now" (and the status line) from the helper's own `list`
/// and `status` over D-Bus, and "Listening" from a local `/proc` scan --
/// the initial load this crate lacked before this task (see this module's
/// own doc comment), and the same thing a successful open re-runs through
/// [`present_open_dialog`]'s `on_opened` hook.
///
/// Neither read blocks the UI thread: the D-Bus round trip already yields
/// at every `.await` -- the same `glib::spawn_future_local` shape
/// `open_now.rs`'s close button and `open_dialog.rs`'s Open button already
/// use for their own calls -- and the scan, an ordinary blocking file read,
/// runs on GLib's own I/O thread pool via `gio::spawn_blocking`, never on
/// this one.
///
/// The scan and the D-Bus fetch are awaited one after the other inside the
/// same spawned future, not as two independent futures racing each other.
/// `listening`'s two setters (`set_services`, called from the scan's own
/// result; `set_open_ports`, called from the helper's) each rebuild every
/// row, and two futures calling them in an unpredictable order could let
/// whichever finished second silently discard the row click handlers
/// `wire_listening_open_buttons` had just attached to rows that, by then,
/// no longer exist. Sequencing them still blocks nothing: `.await` yields
/// back to the main loop regardless of what runs next.
///
/// A failure to reach the helper is not an empty list -- see `open_now.rs`'s
/// and `status_bar.rs`'s own module docs for why conflating those two facts
/// is this project's characteristic defect. The listening scan is
/// independent of the helper entirely and still renders even when the
/// helper cannot be reached; nothing in this codebase today makes `/proc`
/// itself unreadable, but a failure there is logged rather than silently
/// treated as "nothing is listening" regardless.
fn refresh(
    window: &adw::ApplicationWindow,
    open_now: &OpenNowSection,
    listening: &ListeningSection,
    status_bar: &StatusBar,
) {
    let window = window.clone();
    let open_now = open_now.clone();
    let listening = listening.clone();
    let status_bar = status_bar.clone();
    glib::spawn_future_local(async move {
        let scanned =
            gtk::gio::spawn_blocking(|| porthole_core::listening::scan(&RealProcFs)).await;
        match scanned {
            Ok(Ok(services)) => listening.set_services(&services),
            Ok(Err(e)) => {
                eprintln!("porthole-gui: could not scan listening services: {e}");
            }
            Err(_) => {
                eprintln!("porthole-gui: the listening scan panicked");
            }
        }

        match fetch_helper_snapshot().await {
            Ok(snapshot) => {
                let open_ports: Vec<u16> = snapshot.rules.iter().map(|r| r.port).collect();
                open_now.set_rules(&snapshot.rules);
                status_bar.set_status(&snapshot.status);
                listening.set_open_ports(&open_ports);
            }
            Err(message) => {
                open_now.set_unreachable(&message);
                status_bar.set_unreachable(&message);
            }
        }

        wire_listening_open_buttons(&window, &open_now, &listening, &status_bar);
    });
}

/// Parses the one shape `adw::BreakpointCondition::new_length` with
/// `MaxWidth`/`Px` ever produces from `to_string`: `"max-width: 400px"`,
/// confirmed against the real object in a container (GTK4 is not, and must
/// not be, installed on the development host this was written on, so this
/// could not be confirmed any other way -- see `tests/window.rs`'s own
/// container notes). Returns `None` for anything else rather than
/// guessing.
fn max_width_px(condition_text: &str) -> Option<f64> {
    let after = condition_text.split("max-width:").nth(1)?;
    let digits: String = after
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    digits.parse().ok()
}
