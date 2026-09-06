//! The "Open now" section: the top half of the main window, showing every
//! rule the helper currently reports as open. The spec's own ordering --
//! what is open before what could be opened -- is why `window.rs` appends
//! this section's widget first.
//!
//! [`OpenNowSection`] is `refreshable from a rule list`: `set_rules` is the
//! whole way data reaches it. It does not fetch that list itself; whatever
//! calls `set_rules` is responsible for having gotten it from the helper's
//! `list` over D-Bus (`porthole_core::ipc::WireRule`).
//!
//! The one thing this section *does* reach the helper for on its own is a
//! close: each row's close button calls `close_by_id` directly (over the
//! **system** bus -- the same bus the CLI reaches the helper on by default,
//! never the session bus the GUI's own `adw::Application` id lives on; see
//! `app.rs`'s module doc for why those two are not the same bus despite
//! sharing a name), then drops the closed rule from its own list and
//! re-renders -- no second `list` round trip needed, since the caller
//! already knows the `id` it just asked the helper to close. The helper's
//! own response is only checked for success or failure here, not read for
//! its content. A close that fails shows the helper's own message in an
//! `adw::Toast`, verbatim: milestone 2
//! went to real trouble to stop the CLI from double-rendering exactly these
//! strings, and a GUI toast must not reintroduce that.
//!
//! The countdown's rendering never calls the real clock itself; it always
//! goes through `current_time`, which asks whatever
//! `porthole_core::clock::Clock` was injected at construction --
//! [`OpenNowSection::new`] injects the real `SystemClock`, and
//! [`OpenNowSection::with_clock`] lets a caller supply a different one. A
//! test builds a `Clock` it can advance itself (e.g. one backed by a shared
//! `Cell`), injects it via `with_clock`, moves it forward directly, and
//! calls [`OpenNowSection::refresh`] to make the display catch up -- no
//! sleep needed, and no method on this section ever accepts a raw time
//! value that could freeze it. That is deliberate: a `pub fn` taking a
//! `u64` and overriding this section's idea of "now" from then on is
//! reachable from any caller, test or not, and freezing the clock
//! permanently is the exact failure the countdown exists to avoid. Only
//! `new()` is what the real application ever calls; nothing in this crate
//! calls `with_clock` outside of tests.
//!
//! `refresh()` itself carries no time value and cannot freeze anything --
//! it only recomputes every row's countdown against whatever the injected
//! clock currently reports, the same thing a `glib::timeout_add_seconds_local`
//! fired once a second already does unprompted in the real application.
//! Calling it extra times in production is inert.
//!
//! ## A failure to reach the helper is not an empty list
//!
//! `window.rs` (task 6) is what actually calls `set_rules`, fed from the
//! helper's `list` over D-Bus -- and that round trip can fail before it
//! ever produces a list at all: no bus, no helper process, or a call the
//! helper answered with a typed error (a polkit denial among them, but not
//! only that -- a `StateStore` read failure inside the helper reaches this
//! crate exactly the same way, see `window.rs`'s own `HelperFailure` doc
//! comment for why the wording below does not claim which one happened).
//! [`OpenNowSection::set_unreachable`] and [`OpenNowSection::set_errored`]
//! are the states for exactly that -- two different facts (no answer at
//! all, versus an answer that was itself an error), both sharing one
//! widget, [`Inner::error_page`], with different titles, and both distinct
//! from a repurposed calm `status_page`. Rendering "No ports open" when the
//! true state is "I could not ask" is this project's characteristic defect
//! -- the same shape that in milestone 3 told an unprivileged user their
//! port was already reachable when porthole had merely been denied
//! permission to look -- reproduced here at the one layer left that could
//! still make it. `error_page` carries a `dialog-error-symbolic` icon and
//! the `error` style class, the calm page carries neither (see
//! `tests/open_now.rs`'s own empty-state test for exactly what it checks),
//! and the message shown is whatever the caller passed, verbatim -- see
//! `status_bar.rs`'s own module doc for why the same distinction has to
//! survive there too, worded so it never claims what porthole did not
//! confirm.
//!
//! ## Before the first answer arrives
//!
//! [`Inner::loading_page`] is what this section shows before `set_rules`,
//! `set_unreachable` or `set_errored` has ever been called -- a fourth,
//! neutral widget, not the calm `status_page`. "No ports open" is a
//! confirmed fact this section has not yet earned the right to state; a
//! zbus proxy carries no default per-call timeout, so without this,
//! construction would assert that confirmed fact for as long as a
//! live-but-hung helper took to answer, which is unbounded. An
//! indeterminate initial state is the honest one.
//!
//! ## A rule open to anyone is marked, here too
//!
//! [`subtitle_for`] already renders "open to anyone" for an anywhere-scoped
//! rule, distinct from "open to 10.10.10.0/24" for a network-scoped one --
//! but text alone reads as the same weight at a glance, and the most
//! exposed state porthole can produce is exactly the row a user scanning
//! quickly, not reading every subtitle, most needs to be able to spot.
//! `open_dialog.rs`'s target list marks this identical choice with a
//! `dialog-warning-symbolic` icon (never colour alone -- colour fails a
//! colour-blind user and a high-contrast theme), and `listening_section.rs`
//! marks a lesser concern (`BeyondReach`) the same way; a rule already open
//! to anyone, here, now used the same icon as neither. Every anywhere-
//! scoped row gets it too, dry -- no scolding tooltip, matching the spec's
//! own tone rule for "Anyone" (`open_dialog.rs`'s `anyone_note`).

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use porthole_core::clock::{Clock, SystemClock};
use porthole_core::ipc::{PortholeProxy, WireRule};

/// One rendered rule: the widgets `Inner::rows` needs to update or remove
/// later, plus the one piece of the wire data the countdown needs on every
/// tick. Everything else about the rule (title, subtitle) is baked into the
/// row once, at construction, since none of it changes after that.
struct Row {
    expires_at: u64,
    row: adw::ActionRow,
    countdown_label: gtk::Label,
    close_button: gtk::Button,
    /// `Some` only for a rule open to anyone. [`OpenNowSection::is_marked_significant`]
    /// does not trust this field's mere `Some`-ness -- that would only
    /// prove an icon was *constructed*, not that it was ever actually
    /// attached to `row` -- so it also checks the icon's own `parent()`
    /// against the live widget tree (see `open_dialog.rs`'s own
    /// `TargetRow::significant_icon` for the identical pattern, and the
    /// reason it exists).
    significant_icon: Option<gtk::Image>,
}

struct Inner {
    /// What `PortholeWindow` appends into its `content()` box. Holds
    /// exactly one child at a time: `loading_page` before any answer has
    /// arrived, `status_page` once the list is confirmed empty,
    /// `error_page` when the helper could not be reached or answered with
    /// an error, `group` otherwise.
    container: gtk::Box,
    group: adw::PreferencesGroup,
    status_page: adw::StatusPage,
    /// A **different** widget from `status_page`, not a relabelling of it
    /// -- see this module's own doc comment on why a failure to reach the
    /// helper must never render as the calm empty state.
    error_page: adw::StatusPage,
    /// A **different** widget again -- see this module's own doc comment on
    /// why the calm "No ports open" claim must not be the default before
    /// this section has actually heard back from anything.
    loading_page: adw::StatusPage,
    rows: RefCell<Vec<Row>>,
    /// The last list `set_rules` was given, kept so a successful close can
    /// drop exactly the one rule that closed and re-render from the rest,
    /// without a second `list` call.
    rules: RefCell<Vec<WireRule>>,
    /// Injected at construction -- `OpenNowSection::new()` supplies the real
    /// `SystemClock`; `with_clock` lets a caller (a test) supply another.
    /// Never swapped after construction, which is what makes it safe: there
    /// is no method that changes which clock a live section reads.
    clock: Box<dyn Clock>,
    toast_overlay: RefCell<Option<adw::ToastOverlay>>,
}

impl Inner {
    fn current_time(&self) -> u64 {
        self.clock.now()
    }

    fn refresh_countdown_labels(&self) {
        let current = self.current_time();
        for row in self.rows.borrow().iter() {
            row.countdown_label
                .set_label(&format_countdown(row.expires_at, current));
        }
    }

    fn show_toast(&self, message: &str) {
        if let Some(overlay) = self.toast_overlay.borrow().as_ref() {
            overlay.add_toast(adw::Toast::new(message));
        }
    }
}

/// "MM:SS left" while there is time left, "until reboot" for the wire's own
/// `expires_at == 0` until-reboot sentinel (never rendered as a duration --
/// that would be a countdown to 1970), and "closing" once the deadline has
/// passed rather than a negative duration nobody could read sensibly.
fn format_countdown(expires_at: u64, current: u64) -> String {
    if expires_at == 0 {
        return "until reboot".to_string();
    }
    if expires_at <= current {
        return "closing".to_string();
    }
    let remaining = expires_at - current;
    format!("{:02}:{:02} left", remaining / 60, remaining % 60)
}

/// [`OpenNowSection::set_unreachable`]'s title -- no answer came back at
/// all.
const UNREACHABLE_TITLE: &str = "Porthole helper unreachable";

/// [`OpenNowSection::set_errored`]'s title -- the helper answered, and the
/// answer was a typed error. Deliberately shares no wording with
/// [`UNREACHABLE_TITLE`] ("unreachable" is not true of a helper that just
/// responded) and does not say "refused": that error can be a polkit
/// denial, but it can equally be a `StateStore` failure inside the helper,
/// which is not a decision anyone made -- see `window.rs`'s own
/// `HelperFailure` doc comment.
const ERRORED_TITLE: &str = "Porthole helper reported an error";

fn subtitle_for(rule: &WireRule) -> String {
    if rule.scope == "anywhere" {
        "open to anyone".to_string()
    } else {
        format!("open to {}", rule.target)
    }
}

// Item 7's own marking (built in `apply`, below) uses `open_dialog.rs`'s
// own `anyone_note()` for its tooltip, called directly rather than kept as
// a second, separate copy of the sentence -- an earlier version of this
// module did exactly that, as a private constant worded slightly
// differently ("Open to anyone…" vs. `anyone_note()`'s own "Opens the port
// to anyone…"), which is precisely the drift `open_dialog.rs`'s own module
// doc says keeping this sentence to one function is meant to rule out.

/// The helper's own rendered text from a D-Bus method error, verbatim.
///
/// Mirrors `porthole-cli/src/client.rs::from_dbus`'s extraction of the same
/// `detail` field, for the identical reason: the helper already phrased
/// this for a person, and rebuilding a message from the error name would
/// double or invent wording nobody asked for.
fn helper_message(e: &zbus::Error) -> String {
    if let zbus::Error::MethodError(name, detail, _) = e {
        detail.clone().unwrap_or_else(|| name.to_string())
    } else {
        e.to_string()
    }
}

async fn close_by_id_over_dbus(id: &str) -> Result<(), String> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|e| format!("could not reach the porthole helper: {e}"))?;
    let proxy = PortholeProxy::new(&connection)
        .await
        .map_err(|e| format!("could not reach the porthole helper: {e}"))?;
    proxy
        .close_by_id(id, false, false)
        .await
        .map_err(|e| helper_message(&e))?;
    Ok(())
}

/// Replaces `inner`'s rule list and rebuilds every row from scratch. The
/// close button's own success path calls this too (with the closed rule
/// dropped), which is why this is a free function taking `&Rc<Inner>`
/// rather than a `&self` method -- it has to be callable from inside a
/// `glib::spawn_future_local` closure that only has an `Rc<Inner>`, not an
/// `OpenNowSection`.
fn apply(inner: &Rc<Inner>, rules: &[WireRule]) {
    inner.rules.replace(rules.to_vec());

    for row in inner.rows.replace(Vec::new()) {
        inner.group.remove(&row.row);
    }

    // A successful `set_rules` -- even an empty one -- means the helper
    // *was* reached and answered, so any previous "could not reach"/
    // "errored" state, or the initial "not answered yet" one, is stale and
    // must go, the same way `error_page` and `loading_page` displace
    // `group` and `status_page` in `apply_error` below.
    if inner.error_page.parent().is_some() {
        inner.container.remove(&inner.error_page);
    }
    if inner.loading_page.parent().is_some() {
        inner.container.remove(&inner.loading_page);
    }

    if rules.is_empty() {
        if inner.group.parent().is_some() {
            inner.container.remove(&inner.group);
        }
        if inner.status_page.parent().is_none() {
            inner.container.append(&inner.status_page);
        }
        return;
    }

    if inner.status_page.parent().is_some() {
        inner.container.remove(&inner.status_page);
    }
    if inner.group.parent().is_none() {
        inner.container.append(&inner.group);
    }

    let current = inner.current_time();
    let mut rows = Vec::with_capacity(rules.len());
    for rule in rules {
        let action_row = adw::ActionRow::builder()
            .title(format!("{}/{}", rule.port, rule.protocol))
            .subtitle(subtitle_for(rule))
            .build();

        // Item 7: the most exposed state porthole can produce, marked the
        // same way the other two surfaces already mark the identical
        // (`open_dialog.rs`) or a lesser (`listening_section.rs`'s
        // `BeyondReach`) concern -- an icon, not colour alone, and no
        // alarming wording in its tooltip (see the doc comment above).
        let significant_icon = if rule.scope == "anywhere" {
            let icon = gtk::Image::from_icon_name("dialog-warning-symbolic");
            icon.add_css_class("warning");
            icon.set_valign(gtk::Align::Center);
            icon.set_tooltip_text(Some(&crate::open_dialog::anyone_note()));
            action_row.add_prefix(&icon);
            Some(icon)
        } else {
            None
        };

        let countdown_label = gtk::Label::builder()
            .label(format_countdown(rule.expires_at, current))
            .valign(gtk::Align::Center)
            .css_classes(["dim-label"])
            .build();
        action_row.add_suffix(&countdown_label);

        let close_button = gtk::Button::builder()
            .icon_name("user-trash-symbolic")
            .valign(gtk::Align::Center)
            .tooltip_text("Close this port")
            .css_classes(["flat"])
            .build();
        action_row.add_suffix(&close_button);

        let id_for_click = rule.id.clone();
        let inner_for_click = inner.clone();
        close_button.connect_clicked(move |_| {
            let inner = inner_for_click.clone();
            let id = id_for_click.clone();
            glib::spawn_future_local(async move {
                match close_by_id_over_dbus(&id).await {
                    Ok(()) => apply_close(&inner, &id),
                    Err(message) => inner.show_toast(&message),
                }
            });
        });

        inner.group.add(&action_row);
        rows.push(Row {
            expires_at: rule.expires_at,
            row: action_row,
            countdown_label,
            close_button,
            significant_icon,
        });
    }
    inner.rows.replace(rows);
}

/// The close button's own success path: drops rule `id` from `inner.rules`
/// and re-renders from what remains, via `apply` above -- unless `id` is no
/// longer in that list at all. A close is a `glib::spawn_future_local`
/// awaiting a reply, and nothing about it can cancel or reorder against
/// whatever else happens to `inner.rules` while it waits; if that list was
/// replaced in the meantime (cleared to unconfirmed by an error state, or
/// swapped for a fresher one by a later `set_rules`) and no longer contains
/// `id`, it is not the list this close was issued against, and computing
/// "remaining" from it would render state nobody confirmed -- including,
/// starting from an emptied list, `apply`'s own calm empty-list rendering
/// displacing whatever this section was showing instead.
fn apply_close(inner: &Rc<Inner>, id: &str) {
    let rules = inner.rules.borrow();
    if !rules.iter().any(|r| r.id == id) {
        return;
    }
    let remaining: Vec<WireRule> = rules.iter().filter(|r| r.id != id).cloned().collect();
    drop(rules);
    apply(inner, &remaining);
}

/// Replaces whatever `inner.container` was showing with `error_page`,
/// titled `title` and described by `message` -- the shared shape behind
/// [`OpenNowSection::set_unreachable`] and [`OpenNowSection::set_errored`],
/// which differ only in which title they pass. Clears `rows`/`rules` too:
/// whatever list this section last had is now unconfirmed, not merely
/// stale, so it must not keep being shown (or handed back to a close
/// button) as if it still held.
fn apply_error(inner: &Rc<Inner>, title: &str, message: &str) {
    inner.rules.replace(Vec::new());
    for row in inner.rows.replace(Vec::new()) {
        inner.group.remove(&row.row);
    }

    if inner.group.parent().is_some() {
        inner.container.remove(&inner.group);
    }
    if inner.status_page.parent().is_some() {
        inner.container.remove(&inner.status_page);
    }
    if inner.loading_page.parent().is_some() {
        inner.container.remove(&inner.loading_page);
    }

    inner.error_page.set_title(title);
    inner.error_page.set_description(Some(message));
    if inner.error_page.parent().is_none() {
        inner.container.append(&inner.error_page);
    }
}

/// The top section of the main window: every rule the helper currently
/// reports as open, each with a live countdown and a close button.
#[derive(Clone)]
pub struct OpenNowSection {
    inner: Rc<Inner>,
}

impl Default for OpenNowSection {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenNowSection {
    pub fn new() -> Self {
        Self::with_clock(Box::new(SystemClock))
    }

    /// Same construction as [`OpenNowSection::new`], but reads time through
    /// `clock` instead of the real one.
    ///
    /// Not `#[cfg(test)]`: `tests/open_now.rs` is a separate integration-test
    /// crate that links this library as built for the `test` *binary*, not
    /// with `cfg(test)` set on the *library* -- an attribute here would just
    /// compile this constructor out from under it, silently, the moment
    /// anyone tried to use it from there. A constructor parameter is the
    /// actual seam -- the same pattern `porthole_core::engine::Engine::new`
    /// already uses for its own `Clock` (there as a borrowed `&'a dyn
    /// Clock`; owned here as `Box<dyn Clock>`, since `Inner` has to outlive
    /// the borrow that constructed it -- it is kept alive by `'static`
    /// GTK/glib closures for as long as this section's widgets exist).
    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        let group = adw::PreferencesGroup::builder().title("Open now").build();

        // "No ports open" is this machine's normal state, not a problem --
        // a plain status page, no warning icon, no error styling. Presenting
        // it as trouble would teach the user to ignore the one part of this
        // window that should mean something.
        let status_page = adw::StatusPage::builder()
            .title("No ports open")
            .description("Open a port below when you need one.")
            .icon_name("network-wired-symbolic")
            .build();

        // The other case an empty list can mean: porthole did not confirm
        // there is nothing open, it could not ask (or asked and the helper
        // answered with an error). A
        // `dialog-error-symbolic` icon and the `error` style class -- both
        // absent from `status_page` above -- are what make
        // `tests/open_now.rs`'s own test able to tell the two apart
        // structurally, not just by title. See this module's own doc
        // comment. The title itself is set per call by `apply_error`
        // (`set_unreachable`/`set_errored` each pass their own); the one
        // given here at construction is only the default until either is
        // first called.
        let error_page = adw::StatusPage::builder()
            .title(UNREACHABLE_TITLE)
            .icon_name("dialog-error-symbolic")
            .css_classes(["error"])
            .build();

        // Shown before any answer has arrived -- see this module's own
        // doc comment on why the calm `status_page` above must not be the
        // default. Neutral: no error/warning styling, since not having
        // heard back yet is not itself trouble.
        let loading_page = adw::StatusPage::builder()
            .title("Checking what's open…")
            .icon_name("content-loading-symbolic")
            .build();

        let container = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .build();
        container.append(&loading_page);

        let inner = Rc::new(Inner {
            container,
            group,
            status_page,
            error_page,
            loading_page,
            rows: RefCell::new(Vec::new()),
            rules: RefCell::new(Vec::new()),
            clock,
            toast_overlay: RefCell::new(None),
        });

        // Keeps the on-screen countdown live on its own, without anything
        // else asking: once a second, recompute every row's countdown text
        // against whatever `current_time` reports. `tests/open_now.rs`'s
        // activations are brief enough that this is unlikely to fire during
        // a test at all, and harmless if it does -- `refresh_countdown_labels`
        // only recomputes text from state a test already controls, it does
        // not change that state itself.
        let tick_inner = inner.clone();
        glib::timeout_add_seconds_local(1, move || {
            tick_inner.refresh_countdown_labels();
            glib::ControlFlow::Continue
        });

        Self { inner }
    }

    /// The widget `PortholeWindow::content()` appends this section's
    /// contribution as.
    pub fn widget(&self) -> &gtk::Box {
        &self.inner.container
    }

    /// Lets `PortholeWindow` supply the overlay a failed close is reported
    /// through. Never calling this just means a failed close has nowhere to
    /// show its message -- true only in a test, since `PortholeWindow`
    /// always calls it.
    pub fn set_toast_overlay(&self, overlay: &adw::ToastOverlay) {
        *self.inner.toast_overlay.borrow_mut() = Some(overlay.clone());
    }

    pub fn set_rules(&self, rules: &[WireRule]) {
        apply(&self.inner, rules);
    }

    /// The state for a `list`/`status` round trip that produced no answer
    /// at all -- no bus, no helper process, the connection lost mid-call.
    /// See this module's own doc comment for why this is a distinct widget
    /// from the calm empty state, not a relabelling of it, and distinct
    /// again from [`OpenNowSection::set_errored`]. `message` is shown
    /// verbatim, the same convention `helper_message` already holds for a
    /// failed close.
    pub fn set_unreachable(&self, message: &str) {
        apply_error(&self.inner, UNREACHABLE_TITLE, message);
    }

    /// The other failure state: the helper answered, and the answer was a
    /// typed error -- a polkit denial is the common case, but not the only
    /// one (a `StateStore` failure inside the helper reaches here the same
    /// way), so this does not claim which. Same widget as
    /// [`OpenNowSection::set_unreachable`], a different title -- see this
    /// module's own doc comment for why "unreachable" would be a false
    /// claim here. `message` is the helper's own text, verbatim.
    pub fn set_errored(&self, message: &str) {
        apply_error(&self.inner, ERRORED_TITLE, message);
    }

    /// `Some` only while the list is confirmed empty -- once there is a
    /// row, the helper could not be reached or answered with an error
    /// ([`OpenNowSection::error_page`]), or no answer has arrived yet
    /// ([`OpenNowSection::loading_page`]), this section shows something
    /// else instead.
    pub fn status_page(&self) -> Option<adw::StatusPage> {
        if self.inner.status_page.parent().is_some() {
            Some(self.inner.status_page.clone())
        } else {
            None
        }
    }

    /// `Some` only while [`OpenNowSection::set_unreachable`]'s or
    /// [`OpenNowSection::set_errored`]'s state is showing -- a real,
    /// distinct widget from [`OpenNowSection::status_page`], never both at
    /// once. A test reads this (and its title, its icon, and its CSS
    /// classes) rather than trusting that "the list is empty" and "the
    /// helper could not be reached" render the same way just because both
    /// start from zero rows.
    pub fn error_page(&self) -> Option<adw::StatusPage> {
        if self.inner.error_page.parent().is_some() {
            Some(self.inner.error_page.clone())
        } else {
            None
        }
    }

    /// `Some` only before this section has ever heard back from anything
    /// -- the very first widget a freshly constructed section shows, and
    /// gone for good the moment `set_rules`, `set_unreachable` or
    /// `set_errored` is called even once. See this module's own doc
    /// comment for why the calm `status_page` must not be that first
    /// widget instead.
    pub fn loading_page(&self) -> Option<adw::StatusPage> {
        if self.inner.loading_page.parent().is_some() {
            Some(self.inner.loading_page.clone())
        } else {
            None
        }
    }

    pub fn rows(&self) -> Vec<adw::ActionRow> {
        self.inner
            .rows
            .borrow()
            .iter()
            .map(|r| r.row.clone())
            .collect()
    }

    pub fn close_button_for(&self, index: usize) -> Option<gtk::Button> {
        self.inner
            .rows
            .borrow()
            .get(index)
            .map(|r| r.close_button.clone())
    }

    /// Item 7: whether row `index` carries the "open to anyone" marking,
    /// checked against the live widget tree -- the icon's own `parent()`
    /// -- rather than only whether `significant_icon` is `Some`. `Some`
    /// alone would only prove an icon was constructed; a future edit that
    /// built one and never reached `add_prefix` would leave it `Some`
    /// while nothing actually rendered, and `parent()` is what catches
    /// that. Same shape as `OpenDialog::is_marked_significant`, which
    /// checks `parent()` for the identical reason -- an earlier version
    /// of this accessor checked `is_some()` alone, the exact defect that
    /// method's own doc comment was written to rule out.
    pub fn is_marked_significant(&self, index: usize) -> bool {
        self.inner.rows.borrow().get(index).is_some_and(|r| {
            r.significant_icon
                .as_ref()
                .is_some_and(|icon| icon.parent().is_some())
        })
    }

    /// The countdown text as it actually reads on screen right now --
    /// `row.countdown_label`'s real, currently-displayed `gtk::Label` text,
    /// not a value recomputed independently of it. A countdown that is
    /// correct in an accessor but stale on the widget the user is actually
    /// looking at is exactly the failure this section exists to avoid, so
    /// this reads the same property a person would see.
    pub fn countdown_text(&self, index: usize) -> String {
        self.inner.rows.borrow()[index]
            .countdown_label
            .label()
            .to_string()
    }

    /// Recomputes every row's countdown label against whatever the injected
    /// clock currently reports, and writes the result to the real widget.
    /// Takes no time value and cannot freeze anything -- it is exactly what
    /// the once-a-second `glib::timeout_add_seconds_local` in `new()` already
    /// calls unprompted. A test that moves an injected clock forward (see
    /// `with_clock`) calls this afterward to make the display catch up,
    /// without waiting a real second for the timer to do it.
    pub fn refresh(&self) {
        self.inner.refresh_countdown_labels();
    }

    /// Drives the same state change a close button's own success reply
    /// does, without going through `close_by_id_over_dbus` -- that function
    /// opens a real system-bus connection, and `tests/open_now.rs` runs
    /// inside this milestone's own container, which has no system bus at
    /// all (see `tests/window.rs`'s own module doc for why), so a close's
    /// success reply can never actually arrive there. This is the seam that
    /// lets a test still put a real `OpenNowSection` through the one
    /// interleaving that matters -- a refresh failure landing while a close
    /// is in flight, then the close resolving after -- the same way
    /// [`OpenNowSection::with_clock`] is `pub`, not `#[cfg(test)]`, for the
    /// identical reason: this crate's own integration tests link the
    /// library as a `test` binary, not with `cfg(test)` set on the library
    /// itself. Nothing in this crate calls this outside of tests; the real
    /// close button reaches the same underlying logic through
    /// `close_by_id_over_dbus`'s own `Ok(())` arm.
    pub fn simulate_close_succeeded(&self, id: &str) {
        apply_close(&self.inner, id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure-function coverage of the countdown's text, independent of GTK --
    // these run in the crate's ordinary unit-test binary (no widget is
    // touched, so no GTK initialization is needed), unlike everything in
    // `tests/open_now.rs`.

    #[test]
    fn until_reboot_is_the_wire_sentinel_not_a_duration() {
        assert_eq!(format_countdown(0, 1_000), "until reboot");
    }

    #[test]
    fn time_left_counts_down_in_minutes_and_seconds() {
        assert_eq!(format_countdown(3_600, 60), "59:00 left");
        assert_eq!(format_countdown(3_600, 121), "57:59 left");
    }

    #[test]
    fn an_expired_rule_reads_as_closing_not_a_negative_duration() {
        assert_eq!(format_countdown(10, 70), "closing");
    }

    #[test]
    fn the_exact_expiry_second_reads_as_closing_not_zero_left() {
        assert_eq!(format_countdown(100, 100), "closing");
    }

    // `helper_message` is the one piece of the close path with no GTK, no
    // D-Bus connection and no async runtime in it -- and it is the property
    // the brief calls most important ("do not re-word the helper's
    // message"), so it is unit-tested directly rather than left to the
    // untestable-without-a-live-helper rest of the close path. Same shape as
    // `porthole-cli/src/client.rs`'s own `method_error` helper, used there
    // to unit-test `from_dbus`'s identical verbatim pass-through.
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
    fn helper_message_is_the_helpers_detail_verbatim_not_reworded() {
        let e = method_error(
            "com.jacopobriccola.Porthole.AlreadyOpen",
            Some("5173/tcp is already open (open towards 10.10.10.0/24)"),
        );
        assert_eq!(
            helper_message(&e),
            "5173/tcp is already open (open towards 10.10.10.0/24)"
        );
    }

    #[test]
    fn helper_message_falls_back_to_the_error_name_when_there_is_no_detail() {
        let e = method_error("com.jacopobriccola.Porthole.RuleNotFound", None);
        assert_eq!(
            helper_message(&e),
            "com.jacopobriccola.Porthole.RuleNotFound"
        );
    }

    #[test]
    fn helper_message_is_not_empty_or_panicking_for_a_non_method_error() {
        // Not every failure to close is a `MethodError` -- losing the bus
        // connection entirely is a different `zbus::Error` variant, and
        // `helper_message` has to produce *something* readable for it too,
        // even though there is no helper-authored text to preserve verbatim
        // in this case.
        let e = zbus::Error::Failure("the connection was lost".to_string());
        assert_eq!(helper_message(&e), e.to_string());
    }
}
