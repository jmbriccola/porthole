//! The application's single window.
//!
//! `PortholeWindow` wraps a real `adw::ApplicationWindow` rather than
//! subclassing one: nothing here needs a custom GObject property or signal,
//! only a widget tree and two stable extension points -- the `content` box
//! that Tasks 3-6 append their sections into, one per task, and the
//! narrow-width `AdwBreakpoint` the spec requires (`INITIAL_PROMPT.md` §5:
//! "finestra ridimensionabile fino a larghezze strette (`AdwBreakpoint`)").
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

        let toolbar_view = adw::ToolbarView::new();
        toolbar_view.add_top_bar(&adw::HeaderBar::new());
        toolbar_view.set_content(Some(&scroller));

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

        Self {
            window,
            content,
            breakpoint,
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
}
