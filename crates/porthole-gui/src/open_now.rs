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
//! already knows the `id` it just asked the helper to close. What that
//! re-render leaves is also handed to whatever registered
//! [`OpenNowSection::connect_close_succeeded`] -- a rule list this section
//! changed on its own is one nothing else has been told about. The
//! helper's own response is only checked for success or failure here, not
//! read for its content. A close that fails shows the helper's own message
//! in an `adw::Toast`, verbatim: milestone 2
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
//! ## A deadline is not an outcome
//!
//! The countdown reaching zero says the rule's own lifetime is up. It does
//! not say the port closed, and this section has no way to find out: it
//! never calls `list`. So past the deadline the row states the clock --
//! [`TIME_IS_UP`] -- and reports the deadline once, through
//! [`OpenNowSection::connect_expiry_unconfirmed`], to whoever does call
//! `list`. When a list read at least [`EXPIRY_SETTLE_SECONDS`] past that
//! deadline still names the rule, the row says [`STILL_OPEN`] instead, with
//! the marking that goes with it.
//!
//! Those two are different facts and share no word, which is the whole point
//! of the pair. The single word they replaced was "closing", used for both
//! and for a close that had already succeeded -- a claim about the future
//! that nothing here confirmed or retracted, and the exact shape of defect
//! `window.rs`'s and `status_bar.rs`'s own module docs describe one layer
//! further out. A user watched it stand on a row for a port their firewall
//! had already stopped holding open.
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

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use porthole_core::clock::{Clock, SystemClock};
use porthole_core::ipc::{PortholeProxy, WireRule};

/// What a caller registers through
/// [`OpenNowSection::connect_close_succeeded`] to hear that a close this
/// section issued came back successful, carrying the rules this section is
/// showing now that it has re-rendered without the closed one. One slot,
/// not a list: registering again replaces it.
type CloseSucceededCallback = Rc<dyn Fn(&[WireRule])>;

/// What a caller registers through
/// [`OpenNowSection::connect_expiry_unconfirmed`]. Carries nothing: the one
/// thing it says is that a rule's deadline has gone by without this section
/// being told anything, and the answer to that is a fresh list, not a fact
/// about any one row. One slot, not a list: registering again replaces it.
type ExpiryUnconfirmedCallback = Rc<dyn Fn()>;

/// One rendered rule: the widgets `Inner::rows` needs to update or remove
/// later, plus the one piece of the wire data the countdown needs on every
/// tick. Everything else about the rule (title, subtitle) is baked into the
/// row once, at construction, since none of it changes after that.
struct Row {
    expires_at: u64,
    /// When the rule list this row was built from was read -- see
    /// [`format_countdown`] for the one thing it decides.
    listed_at: u64,
    /// Whether [`Inner::refresh_countdown_labels`] has already reported this
    /// row's expiry as unconfirmed. One report per row per rendering: the
    /// tick runs once a second and the reading it is made from does not
    /// change until a new list arrives.
    reported_unconfirmed: Cell<bool>,
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
    /// When `rules` was read, by this section's own clock. A close this
    /// section issued carries it forward unchanged: dropping the closed rule
    /// is fresh knowledge about that rule and about no other, and the rest
    /// of the list is exactly as old as it was. See [`format_countdown`].
    listed_at: Cell<u64>,
    /// Injected at construction -- `OpenNowSection::new()` supplies the real
    /// `SystemClock`; `with_clock` lets a caller (a test) supply another.
    /// Never swapped after construction, which is what makes it safe: there
    /// is no method that changes which clock a live section reads.
    clock: Box<dyn Clock>,
    toast_overlay: RefCell<Option<adw::ToastOverlay>>,
    /// Where a successful close is announced, once this section has
    /// re-rendered without the closed rule. Held on the section rather
    /// than on the close buttons, so it outlives them: `apply` discards
    /// every button it finds and builds new ones.
    on_close_succeeded: RefCell<Option<CloseSucceededCallback>>,
    /// Where "a row's deadline is [`EXPIRY_SETTLE_SECONDS`] behind it and
    /// the list this row came from is older than that" is announced -- see
    /// [`OpenNowSection::connect_expiry_unconfirmed`].
    on_expiry_unconfirmed: RefCell<Option<ExpiryUnconfirmedCallback>>,
}

impl Inner {
    fn current_time(&self) -> u64 {
        self.clock.now()
    }

    /// Rewrites every row's countdown label against whatever the injected
    /// clock reports now, and answers whether any row's deadline has just
    /// gone [`EXPIRY_SETTLE_SECONDS`] by without this section having been
    /// given a list read since. The answer is what [`tick`] turns into one
    /// call to whatever registered
    /// [`OpenNowSection::connect_expiry_unconfirmed`].
    ///
    /// The report is per row and per rendering: `reported_unconfirmed`
    /// stops the once-a-second tick repeating it, and a row rendered from a
    /// list already read past its own settle point never makes it at all,
    /// which is what keeps a list that still names the rule from asking for
    /// another one forever.
    fn refresh_countdown_labels(&self) -> bool {
        let current = self.current_time();
        let mut unconfirmed = false;
        for row in self.rows.borrow().iter() {
            render_countdown(&row.countdown_label, row.expires_at, row.listed_at, current);
            if expiry_has_settled(row.expires_at, current)
                && !expiry_has_settled(row.expires_at, row.listed_at)
                && !row.reported_unconfirmed.replace(true)
            {
                unconfirmed = true;
            }
        }
        unconfirmed
    }

    fn show_toast(&self, message: &str) {
        if let Some(overlay) = self.toast_overlay.borrow().as_ref() {
            overlay.add_toast(adw::Toast::new(message));
        }
    }
}

/// How far past a rule's own deadline a `list` has to have been read before
/// what it says about that rule is treated as the answer about it.
///
/// A `list` read at the deadline itself can still name a rule whose close is
/// under way, and rendering that as "the port did not close" would be a
/// claim on nothing. Before this many seconds, the row states the clock and
/// nothing else; from this many seconds, a list that still names the rule is
/// what the row reports.
///
/// Five seconds is a choice, not a measurement: nothing in this crate knows
/// how long a close takes, and no timing of one went into this number.
const EXPIRY_SETTLE_SECONDS: u64 = 5;

/// The row's own text once its deadline has passed and nothing has been read
/// since the deadline settled. It says what the clock says and stops there:
/// porthole has not been told what happened, and neither "closing" nor
/// "closed" nor "failed" is something it can know at this point.
const TIME_IS_UP: &str = "time is up";

/// The row's own text once a list read at or past the settle point still
/// names this rule. Not the same words as [`TIME_IS_UP`], on purpose: that
/// one is porthole not having heard, and this one is porthole having asked.
const STILL_OPEN: &str = "still open";

/// Whether `at` is far enough past `expires_at` for [`EXPIRY_SETTLE_SECONDS`]
/// to have gone by. Always false for the wire's own `expires_at == 0`
/// until-reboot sentinel, which has no deadline to be past.
fn expiry_has_settled(expires_at: u64, at: u64) -> bool {
    expires_at != 0 && at >= expires_at.saturating_add(EXPIRY_SETTLE_SECONDS)
}

/// "MM:SS left" while there is time left, "until reboot" for the wire's own
/// `expires_at == 0` until-reboot sentinel (never rendered as a duration --
/// that would be a countdown to 1970), and, past the deadline, one of two
/// texts that must not be interchangeable.
///
/// `listed_at` is when the list this row was built from was read.
/// [`TIME_IS_UP`] is what the row says while nothing read since the deadline
/// settled has said anything about this rule. [`STILL_OPEN`] is what it says
/// once a list read at or past that point names the rule anyway -- the
/// helper reporting the port open with its own deadline behind it.
///
/// The word this replaced was "closing", for every one of those -- see this
/// module's own doc comment.
fn format_countdown(expires_at: u64, listed_at: u64, current: u64) -> String {
    if expires_at == 0 {
        return "until reboot".to_string();
    }
    if expires_at > current {
        let remaining = expires_at - current;
        return format!("{:02}:{:02} left", remaining / 60, remaining % 60);
    }
    if expiry_has_settled(expires_at, listed_at) {
        return STILL_OPEN.to_string();
    }
    TIME_IS_UP.to_string()
}

/// Writes [`format_countdown`]'s text onto the real label, and marks the one
/// state that is not routine.
///
/// A port the helper still reports open with its deadline behind it carries
/// the `warning` style class as well as its own words. Never the class
/// alone: colour fails a colour-blind user and a high-contrast theme, which
/// is the same reason the "open to anyone" marking below is an icon and not
/// a tint. Every other state clears the class, since one label is reused
/// across a row's whole life.
fn render_countdown(label: &gtk::Label, expires_at: u64, listed_at: u64, current: u64) {
    let text = format_countdown(expires_at, listed_at, current);
    if expires_at <= current && expiry_has_settled(expires_at, listed_at) {
        label.add_css_class("warning");
    } else {
        label.remove_css_class("warning");
    }
    label.set_label(&text);
}

/// One tick of the countdown, and the one thing a tick can have to say to
/// anybody outside this section.
///
/// A free function taking `&Rc<Inner>` for the same reason [`apply`] is one:
/// it is called from the `glib::timeout_add_seconds_local` closure in
/// `with_clock`, which holds an `Rc<Inner>` and not an [`OpenNowSection`].
/// The callback runs with no borrow of `rows` outstanding.
fn tick(inner: &Rc<Inner>) {
    if !inner.refresh_countdown_labels() {
        return;
    }
    let callback = inner.on_expiry_unconfirmed.borrow().clone();
    if let Some(callback) = callback {
        callback();
    }
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
fn apply(inner: &Rc<Inner>, rules: &[WireRule], listed_at: u64) {
    inner.rules.replace(rules.to_vec());
    inner.listed_at.set(listed_at);

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
            .valign(gtk::Align::Center)
            .css_classes(["dim-label"])
            .build();
        render_countdown(&countdown_label, rule.expires_at, listed_at, current);
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
            listed_at,
            // A row built from a list already read past its own settle point
            // has nothing left to report: the list *is* the answer, and it is
            // already on screen.
            reported_unconfirmed: Cell::new(expiry_has_settled(rule.expires_at, listed_at)),
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
///
/// The early return withholds the announcement too: the list
/// [`OpenNowSection::connect_close_succeeded`]'s callback receives is the
/// one `apply` has just rendered from.
fn apply_close(inner: &Rc<Inner>, id: &str) {
    let rules = inner.rules.borrow();
    if !rules.iter().any(|r| r.id == id) {
        return;
    }
    let remaining: Vec<WireRule> = rules.iter().filter(|r| r.id != id).cloned().collect();
    drop(rules);
    // The list keeps the age it had. Dropping the closed rule is fresh
    // knowledge about that rule; nothing here was read again, so dating the
    // rest as read now would claim a list nobody fetched.
    apply(inner, &remaining, inner.listed_at.get());
    // Cloned out of the cell before the call, so the callback is free to
    // come back into this section.
    let callback = inner.on_close_succeeded.borrow().clone();
    if let Some(callback) = callback {
        callback(&remaining);
    }
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
    inner.listed_at.set(0);
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
            listed_at: Cell::new(0),
            clock,
            toast_overlay: RefCell::new(None),
            on_close_succeeded: RefCell::new(None),
            on_expiry_unconfirmed: RefCell::new(None),
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
            tick(&tick_inner);
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

    /// Registers what to do when a close this section issued comes back
    /// successful -- called with the rules this section is showing once it
    /// has re-rendered without the closed one. Registering again replaces
    /// the callback; never registering means a successful close changes
    /// this section and tells nobody.
    ///
    /// This section holds no reference to any other, and this is how
    /// something that does -- `PortholeWindow` -- learns that the rule list
    /// changed. Same shape as `ListeningSection::connect_open_requested`,
    /// registered from the same place for the same reason.
    pub fn connect_close_succeeded(&self, f: impl Fn(&[WireRule]) + 'static) {
        self.inner.on_close_succeeded.replace(Some(Rc::new(f)));
    }

    /// Registers what to do when a row's own deadline has been
    /// [`EXPIRY_SETTLE_SECONDS`] behind it without this section having been
    /// given a list read since. Called once per such row, from the same
    /// once-a-second tick that keeps the countdown live.
    ///
    /// What it means is only that: a deadline went by and nothing said
    /// anything. It carries no rule and asserts nothing about the port,
    /// because this section knows nothing about the port -- reading `list`
    /// again is the only thing that can settle it, and this section does not
    /// read `list`. `PortholeWindow` is what does; registering again
    /// replaces the callback, and never registering means the deadline goes
    /// by and nothing is re-read.
    pub fn connect_expiry_unconfirmed(&self, f: impl Fn() + 'static) {
        self.inner.on_expiry_unconfirmed.replace(Some(Rc::new(f)));
    }

    /// Drops whatever [`OpenNowSection::connect_expiry_unconfirmed`]
    /// registered, and reports nothing again until something registers
    /// afresh.
    ///
    /// This exists because of what the callback is likely to hold. The
    /// once-a-second `glib::timeout_add_seconds_local` in `with_clock` keeps
    /// this section's `Inner` alive for the life of the process, so anything
    /// `Inner` holds lives that long too -- and the callback `PortholeWindow`
    /// registers holds the window this section is inside. That is a cycle,
    /// and this is the cut: `PortholeWindow` calls this from the same
    /// `destroy` handler that ends its subscription.
    pub fn forget_expiry_unconfirmed(&self) {
        self.inner.on_expiry_unconfirmed.replace(None);
    }

    pub fn set_rules(&self, rules: &[WireRule]) {
        let now = self.inner.current_time();
        apply(&self.inner, rules, now);
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

    /// Whether row `index`'s countdown carries the marking that goes with
    /// [`STILL_OPEN`], checked against the live widget's own style classes
    /// rather than against a value recomputed here. Same reason
    /// [`OpenNowSection::countdown_text`] reads the real label: a state that
    /// is right in an accessor and absent from the widget is the failure
    /// being guarded against.
    pub fn countdown_is_marked_overdue(&self, index: usize) -> bool {
        self.inner.rows.borrow()[index]
            .countdown_label
            .has_css_class("warning")
    }

    /// Recomputes every row's countdown label against whatever the injected
    /// clock currently reports, and writes the result to the real widget.
    /// Takes no time value and cannot freeze anything -- it is exactly what
    /// the once-a-second `glib::timeout_add_seconds_local` in `new()` already
    /// calls unprompted. A test that moves an injected clock forward (see
    /// `with_clock`) calls this afterward to make the display catch up,
    /// without waiting a real second for the timer to do it.
    pub fn refresh(&self) {
        tick(&self.inner);
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
        assert_eq!(format_countdown(0, 0, 1_000), "until reboot");
    }

    #[test]
    fn time_left_counts_down_in_minutes_and_seconds() {
        assert_eq!(format_countdown(3_600, 0, 60), "59:00 left");
        assert_eq!(format_countdown(3_600, 0, 121), "57:59 left");
    }

    #[test]
    fn a_deadline_that_has_just_passed_states_the_clock_and_nothing_else() {
        // The list was read before the deadline, so nothing porthole holds
        // says what happened at it. Not a negative duration, and not a claim
        // about the port either way.
        assert_eq!(format_countdown(100, 40, 101), TIME_IS_UP);
        assert_eq!(format_countdown(100, 40, 100), TIME_IS_UP);
        // Still inside the settle window, so still only the clock.
        assert_eq!(
            format_countdown(100, 100 + EXPIRY_SETTLE_SECONDS - 1, 200),
            TIME_IS_UP
        );
    }

    #[test]
    fn a_list_read_past_the_settle_point_that_still_names_the_rule_says_so() {
        // The list is the authority, it was read late enough to be an answer
        // about this rule, and it named it. That is a different fact from the
        // one above and must not share its words.
        assert_eq!(
            format_countdown(100, 100 + EXPIRY_SETTLE_SECONDS, 200),
            STILL_OPEN
        );
        assert_ne!(STILL_OPEN, TIME_IS_UP);
    }

    #[test]
    fn a_close_that_worked_and_a_close_that_did_not_do_not_share_a_word() {
        // The defect this replaced: one word for both. A close that worked
        // takes the row off screen, so the only row left to read is the one
        // whose close did not happen -- and it must not be readable as the
        // gap before an announcement arrives.
        let in_the_gap = format_countdown(100, 40, 101);
        let still_listed = format_countdown(100, 100 + EXPIRY_SETTLE_SECONDS, 300);
        assert_ne!(in_the_gap, still_listed);
        for text in [&in_the_gap, &still_listed] {
            assert!(
                !text.contains("clos"),
                "the countdown must not name an outcome nothing confirmed: {text}"
            );
        }
    }

    #[test]
    fn an_until_reboot_rule_never_settles_and_never_reports_a_deadline() {
        // `expires_at == 0` is the wire's until-reboot sentinel, not a
        // deadline in 1970 -- so no reading of the clock puts it past one.
        assert!(!expiry_has_settled(0, u64::MAX));
        assert_eq!(format_countdown(0, u64::MAX, u64::MAX), "until reboot");
    }

    #[test]
    fn the_settle_point_is_reached_at_it_and_not_before() {
        assert!(!expiry_has_settled(100, 100 + EXPIRY_SETTLE_SECONDS - 1));
        assert!(expiry_has_settled(100, 100 + EXPIRY_SETTLE_SECONDS));
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
