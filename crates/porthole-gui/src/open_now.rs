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
//! goes through `current_time`, which reads a frozen value if
//! [`OpenNowSection::tick_at`] has ever set one, and only falls back to
//! `porthole_core::clock::SystemClock` otherwise -- so a
//! test can move time forward by calling `tick_at` and reading
//! `countdown_text` again, with no sleep and no dependency on how fast the
//! test happens to run. In the real application, nothing ever calls
//! `tick_at`: a `glib::timeout_add_seconds_local` fired once a second is
//! what keeps the on-screen countdown live there.

use std::cell::{Cell, RefCell};
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
    /// open, `group` otherwise.
    container: gtk::Box,
    group: adw::PreferencesGroup,
    status_page: adw::StatusPage,
    rows: RefCell<Vec<Row>>,
    /// The last list `set_rules` was given, kept so a successful close can
    /// drop exactly the one rule that closed and re-render from the rest,
    /// without a second `list` call.
    rules: RefCell<Vec<WireRule>>,
    /// `None` reads the real clock; `Some(t)` is what `tick_at` freezes it
    /// to, so a test can observe a second tick without sleeping.
    frozen_at: Cell<Option<u64>>,
    toast_overlay: RefCell<Option<adw::ToastOverlay>>,
}

impl Inner {
    fn current_time(&self) -> u64 {
        self.frozen_at.get().unwrap_or_else(|| SystemClock.now())
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

/// The top section of the main window: every rule the helper currently
/// reports as open, each with a live countdown and a close button.
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

        let container = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .build();
        container.append(&status_page);

        let inner = Rc::new(Inner {
            container,
            group,
            status_page,
            rows: RefCell::new(Vec::new()),
            rules: RefCell::new(Vec::new()),
            frozen_at: Cell::new(None),
            toast_overlay: RefCell::new(None),
        });

        // Keeps the on-screen countdown live on its own, without anything
        // else asking: once a second, recompute every row's countdown text
        // against whatever `current_time` reports (live, unless a test has
        // frozen it via `tick_at`). `tests/open_now.rs`'s activations are
        // brief enough that this is unlikely to fire during a test at all,
        // and harmless if it does -- it only recomputes text from state a
        // test already controls, it does not change that state itself.
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

    /// `Some` only while the list is empty -- once there is a row, this
    /// section shows rows, not the status page.
    pub fn status_page(&self) -> Option<adw::StatusPage> {
        if self.inner.status_page.parent().is_some() {
            Some(self.inner.status_page.clone())
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

    pub fn countdown_text(&self, index: usize) -> String {
        let rows = self.inner.rows.borrow();
        format_countdown(rows[index].expires_at, self.inner.current_time())
    }

    /// Freezes this section's clock at `seconds` and immediately re-renders
    /// every countdown against it. The only way a test moves this section's
    /// idea of "now" -- no sleep needed to observe a later tick.
    pub fn tick_at(&self, seconds: u64) {
        self.inner.frozen_at.set(Some(seconds));
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
}
