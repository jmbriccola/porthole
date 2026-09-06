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
//! ever produces a list at all: no bus, no helper process, a polkit denial.
//! [`OpenNowSection::set_unreachable`] is the state for exactly that case,
//! and it is a **third** widget, [`Inner::error_page`], not a repurposing of
//! the calm `status_page` an empty list already shows. Rendering "No ports
//! open" when the true state is "I could not ask" is this project's
//! characteristic defect -- the same shape that in milestone 3 told an
//! unprivileged user their port was already reachable when porthole had
//! merely been denied permission to look -- reproduced here at the one
//! layer left that could still make it. `error_page` carries a warning
//! icon and the `error` style class, the calm page carries neither (see
//! `tests/open_now.rs`'s own empty-state test for exactly what it checks),
//! and the message shown is whatever the caller passed, verbatim -- see
//! `status_bar.rs`'s own module doc for why the same distinction has to
//! survive there too, worded so it never claims what porthole did not
//! confirm.

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
}

struct Inner {
    /// What `PortholeWindow` appends into its `content()` box. Holds
    /// exactly one child at a time: `status_page` when there is nothing
    /// open, `error_page` when the helper could not be reached, `group`
    /// otherwise.
    container: gtk::Box,
    group: adw::PreferencesGroup,
    status_page: adw::StatusPage,
    /// A **different** widget from `status_page`, not a relabelling of it
    /// -- see this module's own doc comment on why a failure to reach the
    /// helper must never render as the calm empty state.
    error_page: adw::StatusPage,
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

fn subtitle_for(rule: &WireRule) -> String {
    if rule.scope == "anywhere" {
        "open to anyone".to_string()
    } else {
        format!("open to {}", rule.target)
    }
}

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
    // *was* reached, so any previous "could not reach the helper" state
    // is stale and must go, the same way `error_page` displaces `group`
    // and `status_page` in `apply_unreachable` below.
    if inner.error_page.parent().is_some() {
        inner.container.remove(&inner.error_page);
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
                    Ok(()) => {
                        let remaining: Vec<WireRule> = inner
                            .rules
                            .borrow()
                            .iter()
                            .filter(|r| r.id != id)
                            .cloned()
                            .collect();
                        apply(&inner, &remaining);
                    }
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
        });
    }
    inner.rows.replace(rows);
}

/// Replaces whatever `inner.container` was showing with `error_page`,
/// described by `message` -- the state [`OpenNowSection::set_unreachable`]
/// renders. Clears `rows`/`rules` too: whatever list this section last had
/// is now unconfirmed, not merely stale, so it must not keep being shown
/// (or handed back to a close button) as if it still held.
fn apply_unreachable(inner: &Rc<Inner>, message: &str) {
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
        // there is nothing open, it could not ask at all. A warning icon
        // and the `error` style class -- both absent from `status_page`
        // above -- are what make `tests/open_now.rs`'s own test able to
        // tell the two apart structurally, not just by title. See this
        // module's own doc comment.
        let error_page = adw::StatusPage::builder()
            .title("Porthole helper unreachable")
            .icon_name("dialog-error-symbolic")
            .css_classes(["error"])
            .build();

        let container = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .build();
        container.append(&status_page);

        let inner = Rc::new(Inner {
            container,
            group,
            status_page,
            error_page,
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

    /// The state for a `list` call that never produced a list at all --
    /// see this module's own doc comment for why this is a distinct widget
    /// from the calm empty state, not a relabelling of it. `message` is
    /// shown verbatim, the same convention `helper_message` already holds
    /// for a failed close.
    pub fn set_unreachable(&self, message: &str) {
        apply_unreachable(&self.inner, message);
    }

    /// `Some` only while the list is confirmed empty -- once there is a
    /// row, or the helper could not be reached at all
    /// ([`OpenNowSection::error_page`]), this section shows something
    /// else instead.
    pub fn status_page(&self) -> Option<adw::StatusPage> {
        if self.inner.status_page.parent().is_some() {
            Some(self.inner.status_page.clone())
        } else {
            None
        }
    }

    /// `Some` only while [`OpenNowSection::set_unreachable`]'s state is
    /// showing -- a real, distinct widget from [`OpenNowSection::status_page`],
    /// never both at once. A test reads this (and its icon, and its CSS
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
