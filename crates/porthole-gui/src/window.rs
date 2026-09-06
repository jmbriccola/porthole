//! The application's single window.
//!
//! `PortholeWindow` wraps a real `adw::ApplicationWindow` rather than
//! subclassing one: nothing here needs a custom GObject property or signal,
//! only a widget tree and three stable extension points -- the `content` box
//! that Tasks 3-6 append their sections into, one per task; the narrow-width
//! `AdwBreakpoint` the spec requires (`INITIAL_PROMPT.md` §5: "finestra
//! ridimensionabile fino a larghezze strette (`AdwBreakpoint`)"); and the
//! `AdwToastOverlay` any section can show a toast through, first used by
//! Task 3's close button.
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

use std::ops::Deref;

use adw::prelude::*;

use crate::listening_section::ListeningSection;
use crate::open_dialog::OpenDialog;
use crate::open_now::OpenNowSection;

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

        // Task 5's own affordance: opens a fresh `OpenDialog` -- never a
        // reused one, so a previous attempt's typed port or chosen chip
        // never leaks into the next. `ListeningSection`'s own per-row Open
        // buttons are a second, pre-filled way to reach the same dialog;
        // wiring those up is left to whichever task first calls
        // `ListeningSection::set_services` with real data, since there is
        // nothing to click on an empty list.
        let open_button = gtk::Button::builder()
            .icon_name("list-add-symbolic")
            .tooltip_text("Open a port")
            .build();
        let header_bar = adw::HeaderBar::new();
        header_bar.pack_start(&open_button);

        let toolbar_view = adw::ToolbarView::new();
        toolbar_view.add_top_bar(&header_bar);
        toolbar_view.set_content(Some(&toast_overlay));

        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("Porthole")
            .default_width(480)
            .default_height(560)
            .content(&toolbar_view)
            .build();

        let window_for_open = window.clone();
        open_button.connect_clicked(move |_| {
            let dialog = OpenDialog::new();
            dialog.present(Some(&window_for_open));
        });

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

        Self {
            window,
            content,
            breakpoint,
            toast_overlay,
            open_now,
            listening,
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

    /// The header bar's "Open a port" button, for a test that wants to
    /// check its own state (tooltip, focusability) rather than simulate a
    /// click -- see this constructor's own comment on why the click handler
    /// builds a fresh `OpenDialog` each time instead of one this window
    /// keeps around.
    pub fn open_button(&self) -> &gtk::Button {
        &self.open_button
    }
}
