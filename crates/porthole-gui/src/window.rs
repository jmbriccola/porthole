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
//! No answer at all, a refused request, and a confirmed empty list are
//! three different facts and render as three different things -- see
//! `refresh`'s own doc comment, `open_now.rs`'s and `status_bar.rs`'s
//! module docs for why conflating any pair of them is this project's
//! characteristic defect.

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

/// `content`'s own margin, in CSS pixels, while the window is narrow --
/// down from the ordinary 24px set at construction. Applied through
/// `Breakpoint::add_setters` in [`PortholeWindow::new`]; libadwaita
/// restores the original 24px on its own once the breakpoint stops
/// matching.
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
        // sections start out showing their own *indeterminate* "not
        // answered yet" state (built into `OpenNowSection`/
        // `ListeningSection` themselves, not the calm "nothing open"/
        // "nothing listening" one -- a zbus proxy carries no default
        // per-call timeout, so nothing bounds how long that would
        // otherwise have to stand in for a confirmed fact it has not
        // earned) until `refresh` resolves; `refresh` runs the same path a
        // later explicit refresh does, there is no separate "first load"
        // code.
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

/// Two different facts a `list`/`status` call can fail with, neither of
/// which may render as the other -- see `open_now.rs`'s and
/// `status_bar.rs`'s own module docs for why conflating them is this
/// project's characteristic defect. `Unreachable` is no answer at all: no
/// bus, no helper process, the connection lost mid-call, or this refresh's
/// own bounded wait (`with_timeout`, below) running out. `Refused` is the
/// helper answering with a typed decision it declined -- a polkit denial
/// being the common case, since `list` and `status` both go through the
/// same authorization check `open`/`close` do (see
/// `porthole-helper/src/service.rs`). [`classify_failure`] is what tells
/// the two apart: only a `zbus::Error::MethodError` means the helper
/// actually responded.
enum HelperFailure {
    Unreachable(String),
    Refused(String),
}

fn classify_failure(e: zbus::Error) -> HelperFailure {
    match &e {
        zbus::Error::MethodError(..) => HelperFailure::Refused(helper_message(&e)),
        _ => HelperFailure::Unreachable(format!("could not reach the porthole helper: {e}")),
    }
}

fn apply_failure_to_open_now(open_now: &OpenNowSection, failure: &HelperFailure) {
    match failure {
        HelperFailure::Unreachable(message) => open_now.set_unreachable(message),
        HelperFailure::Refused(message) => open_now.set_refused(message),
    }
}

fn apply_failure_to_status_bar(status_bar: &StatusBar, failure: &HelperFailure) {
    match failure {
        HelperFailure::Unreachable(message) => status_bar.set_unreachable(message),
        HelperFailure::Refused(message) => status_bar.set_refused(message),
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
    Ok(HelperSnapshot { rules, status })
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
/// click handler a previous call to this function had connected -- so a
/// caller must call this again *immediately* after whichever of those two
/// setters it just called, every single time one of them runs, never once
/// at the end of some larger sequence: calling it after a setter that was
/// *skipped* (a failed scan, say, which calls `set_scan_failed` instead of
/// `set_services`) would re-attach a second handler onto buttons that
/// already have one from the last successful render, and each press would
/// open two dialogs. It lives here rather than inside `listening_section.rs`
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

/// Populates "Open now", "Listening" and the status line -- the initial
/// load this crate lacked before this task (see this module's own doc
/// comment), and the same thing a successful open re-runs through
/// [`present_open_dialog`]'s `on_opened` hook.
///
/// The `/proc` scan and the helper round trip run as two **independent**
/// spawned futures below, not sequenced against each other. Each one wires
/// its own rows (`wire_listening_open_buttons`) immediately after whichever
/// of `listening`'s setters it just called -- so there is no shared "wire
/// once, at the end" step left for the two to race over. An earlier draft
/// of this function sequenced the scan before the helper fetch specifically
/// to avoid that race (both eventually called `wire_listening_open_buttons`
/// once, together, at the very end); that avoidance is no longer needed now
/// that wiring happens right where each setter that could change the rows
/// is actually called.
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
/// answered but refused a request is not the same fact as one that never
/// answered at all -- see `open_now.rs`'s and `status_bar.rs`'s own module
/// docs for why conflating either pair is this project's characteristic
/// defect. A `/proc` scan failure is the identical shape one layer down:
/// [`ListeningSection::set_scan_failed`] is that state, not silence plus a
/// stderr line standing in for "nothing is listening".
fn refresh(
    window: &adw::ApplicationWindow,
    open_now: &OpenNowSection,
    listening: &ListeningSection,
    status_bar: &StatusBar,
) {
    {
        let window = window.clone();
        let open_now = open_now.clone();
        let listening = listening.clone();
        let status_bar = status_bar.clone();
        glib::spawn_future_local(async move {
            let scanned =
                gtk::gio::spawn_blocking(|| porthole_core::listening::scan(&RealProcFs)).await;
            match scanned {
                Ok(Ok(services)) => {
                    listening.set_services(&services);
                    wire_listening_open_buttons(&window, &open_now, &listening, &status_bar);
                }
                Ok(Err(e)) => {
                    listening.set_scan_failed(&format!("could not check what is listening: {e}"));
                }
                Err(_) => {
                    listening.set_scan_failed("the listening scan panicked");
                }
            }
        });
    }

    {
        let window = window.clone();
        let open_now = open_now.clone();
        let listening = listening.clone();
        let status_bar = status_bar.clone();
        glib::spawn_future_local(async move {
            match with_timeout(fetch_helper_snapshot(), HELPER_TIMEOUT).await {
                Some(Ok(snapshot)) => {
                    match snapshot.rules {
                        Ok(rules) => {
                            let open_ports: Vec<u16> = rules.iter().map(|r| r.port).collect();
                            open_now.set_rules(&rules);
                            listening.set_open_ports(&open_ports);
                            wire_listening_open_buttons(
                                &window,
                                &open_now,
                                &listening,
                                &status_bar,
                            );
                        }
                        Err(failure) => apply_failure_to_open_now(&open_now, &failure),
                    }
                    match snapshot.status {
                        Ok(status) => status_bar.set_status(&status),
                        Err(failure) => apply_failure_to_status_bar(&status_bar, &failure),
                    }
                }
                Some(Err(failure)) => {
                    apply_failure_to_open_now(&open_now, &failure);
                    apply_failure_to_status_bar(&status_bar, &failure);
                }
                None => {
                    // `with_timeout` won the race: the helper never
                    // answered within `HELPER_TIMEOUT` at all, which is
                    // itself an "unreachable" fact, not a refusal -- the
                    // helper never got the chance to refuse anything.
                    let failure = HelperFailure::Unreachable(
                        "could not reach the porthole helper: timed out".to_string(),
                    );
                    apply_failure_to_open_now(&open_now, &failure);
                    apply_failure_to_status_bar(&status_bar, &failure);
                }
            }
        });
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
    fn a_method_error_is_refused_not_unreachable() {
        // I2: the helper answered here -- a typed refusal, not silence.
        let e = method_error(
            "com.jacopobriccola.Porthole.NotAuthorized",
            Some("not authorized: com.jacopobriccola.Porthole.List"),
        );
        match classify_failure(e) {
            HelperFailure::Refused(message) => {
                assert_eq!(message, "not authorized: com.jacopobriccola.Porthole.List");
            }
            HelperFailure::Unreachable(message) => {
                panic!("a MethodError must classify as Refused, not Unreachable: {message}")
            }
        }
    }

    #[test]
    fn a_non_method_error_is_unreachable_not_refused() {
        // The connection-lost case: no typed answer came back at all.
        let e = zbus::Error::Failure("the connection was lost".to_string());
        match classify_failure(e) {
            HelperFailure::Unreachable(message) => {
                assert!(
                    message.contains("could not reach the porthole helper"),
                    "{message}"
                );
            }
            HelperFailure::Refused(message) => {
                panic!("a non-MethodError must classify as Unreachable, not Refused: {message}")
            }
        }
    }
}
