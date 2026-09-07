//! Runs a real `OpenNowSection` inside an activated `adw::Application`, the
//! same way `tests/window.rs` does and for the identical reason:
//! `harness = false` (see `Cargo.toml`) because cargo's normal test harness
//! spawns each `#[test]` function on its own OS thread, and gtk4-rs locks
//! GTK to whichever thread makes its first call -- a second GTK-touching
//! test thread wedges the whole process. This is its own `[[test]]` target,
//! not a case added to `tests/window.rs`, exactly as that file's own
//! comment asks a later task's implementer to do.
//!
//! Every widget property here is read back *without* pumping the main
//! loop, unlike `tests/window.rs`'s breakpoint checks: these tests assert
//! on properties this section sets directly (title, subtitle, widget
//! presence, the countdown label's actual displayed text), none of which
//! need a GTK layout pass to become true -- only construction, which does
//! need to happen inside a real activation (GTK widgets cannot be built
//! before `gtk_init`, which activation performs).
//!
//! None of these tests read the real clock. `BASE_TIME` is an arbitrary,
//! fixed anchor, and `OpenNowSection::with_clock` is what lets a test
//! supply it directly -- `SharedClock` below is a `Clock` backed by a
//! `Cell` the test keeps its own handle to, so "moving time forward" is
//! just mutating that cell and calling `OpenNowSection::refresh()`, never a
//! method on `OpenNowSection` itself that accepts a raw time value (see
//! `open_now.rs`'s module doc for why that distinction matters: such a
//! method would be reachable from production too, and freezing a live
//! section's clock permanently is the exact failure this section's
//! countdown exists to avoid).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use porthole_core::clock::Clock;
use porthole_core::ipc::WireRule;
use porthole_gui::open_now::OpenNowSection;

/// Identical in shape to `tests/window.rs`'s own `activate` helper: runs `f`
/// inside a real `adw::Application` activation, on the session bus
/// `dbus-run-session` provides (see `tests/container/gui-test.sh`).
fn activate<F: FnOnce(&adw::Application) + 'static>(app_id: &str, f: F) {
    let app = adw::Application::builder().application_id(app_id).build();
    let f = Rc::new(RefCell::new(Some(f)));
    app.connect_activate(move |app| {
        if let Some(f) = f.borrow_mut().take() {
            f(app);
        }
        app.quit();
    });
    app.run_with_args::<&str>(&[]);
}

/// A fixed constant, never read from the real clock. Every test that cares
/// about a specific countdown value builds its fixture and its
/// `SharedClock` from this same constant, so there is exactly one source of
/// "now" per test and no possibility of two independent clock reads landing
/// on either side of a second boundary.
const BASE_TIME: u64 = 1_757_100_000;

/// `PortholeWindow`'s own default window width, in pixels -- the width a
/// height measurement here has to be taken at for the wrapping it sees to
/// be the wrapping a user gets.
const WINDOW_WIDTH_PX: i32 = 480;

/// A `Clock` a test can move forward directly, by mutating the `Cell` it
/// shares with whichever `OpenNowSection` was built with a clone of it via
/// `OpenNowSection::with_clock`. The test keeps the only other handle to
/// that `Cell`; nothing about `OpenNowSection`'s own public API can reach
/// or move it.
#[derive(Clone)]
struct SharedClock(Rc<Cell<u64>>);

impl SharedClock {
    fn at(seconds: u64) -> Self {
        Self(Rc::new(Cell::new(seconds)))
    }

    fn advance_to(&self, seconds: u64) {
        self.0.set(seconds);
    }
}

impl Clock for SharedClock {
    fn now(&self) -> u64 {
        self.0.get()
    }
}

/// A rule as the wire reports it, opened one minute before `base` with a
/// total lifetime of `lifetime_secs` -- so a 3600s (one hour) rule already
/// has 59 minutes left as of `base`, not the full hour a rule just opened
/// would show. `lifetime_secs == 0` is the wire's own until-reboot sentinel
/// and is passed straight through as `expires_at == 0`, never offset.
fn wire_rule(base: u64, port: u16, protocol: &str, target: &str, lifetime_secs: u64) -> WireRule {
    let opened_at = base - 60;
    WireRule {
        id: format!("{port}/{protocol}"),
        port,
        protocol: protocol.to_string(),
        target: target.to_string(),
        scope: "network".to_string(),
        backend: "firewalld".to_string(),
        opened_at,
        expires_at: if lifetime_secs == 0 {
            0
        } else {
            opened_at + lifetime_secs
        },
        uid: 1000,
    }
}

/// "No ports open" is this machine's normal state, not an error. Presenting
/// it as a problem -- a warning icon, an error style, a red anything --
/// teaches the user to ignore the one part of this window that should mean
/// something. Checked structurally (the CSS classes, and that the error
/// state is genuinely absent), not only the text -- text alone would still
/// pass if a later change added `.add_css_class("error")`.
fn an_empty_list_is_a_calm_note_not_an_error() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowEmpty",
        move |_app| {
            let section = OpenNowSection::with_clock(Box::new(SharedClock::at(BASE_TIME)));
            section.set_rules(&[]);
            let note = section.empty_note();
            let text = note.as_ref().map(|n| n.label().to_string());
            let css_classes: Vec<String> = note
                .as_ref()
                .map(|n| n.css_classes().iter().map(|c| c.to_string()).collect())
                .unwrap_or_default();
            let error_showing = section.error_note().is_some();
            let rows_empty = section.rows().is_empty();
            *seen.borrow_mut() = Some((text, css_classes, error_showing, rows_empty));
        },
    );
    let (text, css_classes, error_showing, rows_empty) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    let text = text.ok_or("a confirmed-empty list must show its own note")?;
    if !text.starts_with("No ports open") {
        return Err(format!(
            "expected the confirmed-empty note to say so, got {text:?}"
        ));
    }
    if css_classes.iter().any(|c| c == "error" || c == "warning") {
        return Err(format!(
            "the empty state carries an error/warning CSS class: {css_classes:?}"
        ));
    }
    if error_showing {
        return Err(
            "the \"could not ask\" state must not be on screen alongside a confirmed-empty \
             list"
                .to_string(),
        );
    }
    if !rows_empty {
        return Err("rows must be empty when nothing is open".to_string());
    }
    Ok(())
}

fn each_rule_shows_port_protocol_target_and_a_close_button() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate("com.jacopobriccola.Porthole.Test.OpenNowRow", move |_app| {
        let section = OpenNowSection::with_clock(Box::new(SharedClock::at(BASE_TIME)));
        section.set_rules(&[wire_rule(BASE_TIME, 5173, "tcp", "10.10.10.0/24", 3600)]);
        let rows = section.rows();
        let row_count = rows.len();
        let title = rows.first().map(|r| r.title().to_string());
        let subtitle = rows
            .first()
            .and_then(|r| r.subtitle())
            .map(|s| s.to_string());
        let has_close_button = section.close_button_for(0).is_some();
        *seen.borrow_mut() = Some((row_count, title, subtitle, has_close_button));
    });
    let (row_count, title, subtitle, has_close_button) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if row_count != 1 {
        return Err(format!("expected exactly one row, got {row_count}"));
    }
    if title.as_deref() != Some("5173/tcp") {
        return Err(format!("expected title \"5173/tcp\", got {title:?}"));
    }
    match subtitle.as_deref() {
        Some(s) if s.contains("10.10.10.0/24") => {}
        other => return Err(format!("subtitle must name the target: {other:?}")),
    }
    if !has_close_button {
        return Err("row 0 must have a close button".to_string());
    }
    Ok(())
}

/// Item 7: the most exposed state porthole can produce -- a rule open to
/// anyone -- must be visually distinguishable from an ordinary
/// subnet-scoped one, not just by the subtitle's own text (which already
/// differed) but by shape: a warning icon, mirroring `open_dialog.rs`'s
/// own marking for the identical choice and `listening_section.rs`'s for
/// a lesser one. Both rows render side by side here specifically so a
/// regression that made them look identical again would be caught the way
/// a person scanning the list quickly, not reading every subtitle, would
/// notice it.
fn an_anywhere_scoped_rule_is_marked_and_a_subnet_scoped_one_is_not() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowAnyone",
        move |_app| {
            let section = OpenNowSection::with_clock(Box::new(SharedClock::at(BASE_TIME)));
            let mut anywhere = wire_rule(BASE_TIME, 8080, "tcp", "anywhere", 3600);
            anywhere.scope = "anywhere".to_string();
            let subnet = wire_rule(BASE_TIME, 5173, "tcp", "10.10.10.0/24", 3600);
            section.set_rules(&[anywhere, subnet]);
            *seen.borrow_mut() = Some((
                section.is_marked_significant(0),
                section.is_marked_significant(1),
            ));
        },
    );
    let (anywhere_marked, subnet_marked) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if !anywhere_marked {
        return Err("a rule open to anyone must carry the significant-choice marking".to_string());
    }
    if subnet_marked {
        return Err(
            "a subnet-scoped rule must not carry the marking reserved for \"anyone\"".to_string(),
        );
    }
    Ok(())
}

/// A countdown that renders once and freezes is worse than no countdown: it
/// states a specific remaining time, confidently, and is wrong. This reads
/// `countdown_text`, which is the real `gtk::Label`'s actual displayed text
/// (not a value recomputed independently of the widget) -- so what this
/// test observes changing is the same thing a person looking at the window
/// would see change.
fn the_countdown_is_live_and_counts_down() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowCountdown",
        move |_app| {
            let clock = SharedClock::at(BASE_TIME);
            let section = OpenNowSection::with_clock(Box::new(clock.clone()));
            section.set_rules(&[wire_rule(BASE_TIME, 5173, "tcp", "10.10.10.0/24", 3600)]);
            let first = section.countdown_text(0);
            clock.advance_to(BASE_TIME + 61);
            section.refresh();
            let later = section.countdown_text(0);
            *seen.borrow_mut() = Some((first, later));
        },
    );
    let (first, later) = result.borrow_mut().take().ok_or("activation never ran")?;
    if first == later {
        return Err(format!(
            "the countdown did not change after a tick: still {first:?}"
        ));
    }
    if first != "59:00 left" {
        return Err(format!(
            "expected \"59:00 left\" before the tick, got {first:?}"
        ));
    }
    if later != "57:59 left" {
        return Err(format!(
            "expected \"57:59 left\" after the tick, got {later:?}"
        ));
    }
    Ok(())
}

/// `expires_at == 0` is the wire's own until-reboot sentinel. Rendering it
/// as a duration would produce a countdown to 1970.
fn until_reboot_says_so_instead_of_showing_a_countdown() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowReboot",
        move |_app| {
            let section = OpenNowSection::with_clock(Box::new(SharedClock::at(BASE_TIME)));
            section.set_rules(&[wire_rule(BASE_TIME, 5173, "tcp", "10.10.10.0/24", 0)]);
            *seen.borrow_mut() = Some(section.countdown_text(0));
        },
    );
    let text = result.borrow_mut().take().ok_or("activation never ran")?;
    if text != "until reboot" {
        return Err(format!("expected \"until reboot\", got {text:?}"));
    }
    Ok(())
}

/// The other half of the live-countdown property, and the defect a person
/// found on a Fedora Workstation VM.
///
/// A rule with a few seconds left when the section first renders it must,
/// once that time has genuinely passed, stop counting down -- and what it
/// says instead must be true of what this section actually knows. This
/// section never calls `list`. It knows the deadline arrived and nothing
/// else, so that is all the row may say: not "closing", which is an outcome,
/// and which read identically whether the close had already succeeded or had
/// failed an hour ago.
///
/// Checked on the real widget, via `refresh()`, at three points across the
/// deadline the fixture itself carries: still counting down before it,
/// saying the same thing at it and an hour past it while nothing new has
/// been read, and never marked as something to look at while that is all
/// that is known.
fn an_expired_rule_states_the_clock_and_claims_no_outcome() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowExpired",
        move |_app| {
            let clock = SharedClock::at(BASE_TIME);
            let section = OpenNowSection::with_clock(Box::new(clock.clone()));
            // 65s lifetime, opened 60s before BASE_TIME: 5 seconds left as
            // of BASE_TIME, still a normal countdown at construction. Every
            // clock reading below is taken from the fixture's own
            // `expires_at`, never from that arithmetic repeated by hand.
            let rule = wire_rule(BASE_TIME, 5173, "tcp", "10.10.10.0/24", 65);
            let deadline = rule.expires_at;
            section.set_rules(&[rule]);
            let before = section.countdown_text(0);
            clock.advance_to(deadline);
            section.refresh();
            let at_the_deadline = section.countdown_text(0);
            // An hour later, with no fresher list handed over: still the
            // same thing, because still nothing more is known.
            clock.advance_to(deadline + 3_600);
            section.refresh();
            *seen.borrow_mut() = Some((
                before,
                at_the_deadline,
                section.countdown_text(0),
                section.countdown_is_marked_overdue(0),
            ));
        },
    );
    let (before, at_the_deadline, an_hour_later, marked) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if before != "00:05 left" {
        return Err(format!(
            "expected a live countdown before the deadline, got {before:?}"
        ));
    }
    if at_the_deadline.contains("clos") || an_hour_later.contains("clos") {
        return Err(format!(
            "the row must not name an outcome this section cannot know: {at_the_deadline:?} \
             then {an_hour_later:?}"
        ));
    }
    if at_the_deadline != an_hour_later {
        return Err(format!(
            "nothing was read between these two, so the row must not have changed what it \
             claims: {at_the_deadline:?} then {an_hour_later:?}"
        ));
    }
    if marked {
        return Err(
            "a deadline nobody has checked yet must not be marked as something to look at"
                .to_string(),
        );
    }
    Ok(())
}

/// The case a close that failed produces, and the one the old single word
/// made unreachable: a list read well past a rule's deadline that still
/// names the rule.
///
/// That is a different fact from the one above -- porthole asked, rather
/// than porthole not having heard -- so it must not read the same, and it
/// carries the marking the other does not.
fn a_list_read_past_the_deadline_that_still_names_the_rule_reads_differently() -> Result<(), String>
{
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowStillListed",
        move |_app| {
            let clock = SharedClock::at(BASE_TIME);
            let section = OpenNowSection::with_clock(Box::new(clock.clone()));
            let rule = wire_rule(BASE_TIME, 5173, "tcp", "10.10.10.0/24", 65);
            let deadline = rule.expires_at;
            section.set_rules(std::slice::from_ref(&rule));
            clock.advance_to(deadline);
            section.refresh();
            let unconfirmed = section.countdown_text(0);

            // A minute past the deadline, the helper is asked again and
            // still names the rule. That is the answer, and it is not the
            // one above.
            clock.advance_to(deadline + 60);
            section.set_rules(&[rule]);
            *seen.borrow_mut() = Some((
                unconfirmed,
                section.countdown_text(0),
                section.countdown_is_marked_overdue(0),
            ));
        },
    );
    let (unconfirmed, still_listed, marked) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if unconfirmed == still_listed {
        return Err(format!(
            "a close that has not been checked and a port the helper still reports open past \
             its deadline must not read the same: both said {still_listed:?}"
        ));
    }
    if still_listed.contains("clos") {
        return Err(format!(
            "a port the helper still reports open must not be described as closing or closed: \
             {still_listed:?}"
        ));
    }
    if !marked {
        return Err(
            "a port the helper still reports open past its own deadline must be marked, not \
             left reading like an ordinary row"
                .to_string(),
        );
    }
    Ok(())
}

/// The section cannot settle a passed deadline on its own -- it never calls
/// `list` -- so it says so, once, to whoever does.
///
/// Reported only after the deadline is far enough behind for a list to be an
/// answer about it, and only for a row built from a list read before that
/// point: a row built from a list already read past it has its answer
/// already, and reporting again would ask for a fresh list every second for
/// as long as the rule stayed open.
fn a_passed_deadline_is_reported_once_to_whoever_can_re_read_the_list() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowExpiryReported",
        move |_app| {
            let clock = SharedClock::at(BASE_TIME);
            let section = OpenNowSection::with_clock(Box::new(clock.clone()));
            let reports = Rc::new(Cell::new(0u32));
            let counted = reports.clone();
            section.connect_expiry_unconfirmed(move || counted.set(counted.get() + 1));

            let rule = wire_rule(BASE_TIME, 5173, "tcp", "10.10.10.0/24", 65);
            let deadline = rule.expires_at;
            section.set_rules(std::slice::from_ref(&rule));
            // Right at the deadline: a close may well be under way, and
            // nothing is asked for yet.
            clock.advance_to(deadline);
            section.refresh();
            let at_the_deadline = reports.get();

            // A minute past it, with the list still the one read before.
            clock.advance_to(deadline + 60);
            section.refresh();
            let after = reports.get();
            // Every following tick, with nothing having changed.
            section.refresh();
            section.refresh();
            let after_more_ticks = reports.get();

            // The fresh list arrives and still names the rule. The answer is
            // on screen; nothing more is to be asked.
            section.set_rules(&[rule]);
            section.refresh();
            section.refresh();
            *seen.borrow_mut() = Some((at_the_deadline, after, after_more_ticks, reports.get()));
        },
    );
    let (at_the_deadline, after, after_more_ticks, after_a_fresh_list) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if at_the_deadline != 0 {
        return Err(format!(
            "the deadline itself must not be reported -- a close is ordinarily under way at \
             that moment; got {at_the_deadline}"
        ));
    }
    if after != 1 {
        return Err(format!(
            "a deadline the list cannot yet account for must be reported exactly once, got \
             {after}"
        ));
    }
    if after_more_ticks != 1 {
        return Err(format!(
            "the once-a-second tick must not repeat the report, got {after_more_ticks}"
        ));
    }
    if after_a_fresh_list != 1 {
        return Err(format!(
            "a row built from a list already read past its own deadline has its answer and \
             must ask for nothing, got {after_a_fresh_list}"
        ));
    }
    Ok(())
}

/// Task 6's own case: a failure to reach the helper must not render as
/// "No ports open" -- see `src/open_now.rs`'s own module doc for why
/// conflating "confirmed nothing is open" with "could not ask" is this
/// project's characteristic defect. Checked structurally (icon, CSS
/// classes, and that the calm page is genuinely gone, not merely covered),
/// the same way `an_empty_list_is_a_calm_note_not_an_error` checks
/// the calm state's own icon/CSS rather than only its title.
fn an_unreachable_helper_does_not_render_as_the_calm_empty_state() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowUnreachable",
        move |_app| {
            let section = OpenNowSection::with_clock(Box::new(SharedClock::at(BASE_TIME)));
            section.set_unreachable("could not reach the porthole helper: timed out");
            let calm = section.empty_note();
            let error = section.error_note();
            let icon_name = error
                .as_ref()
                .and_then(|p| p.icon_name())
                .map(|s| s.to_string());
            let css_classes: Vec<String> = error
                .as_ref()
                .map(|p| p.css_classes().iter().map(|c| c.to_string()).collect())
                .unwrap_or_default();
            let description = error
                .as_ref()
                .and_then(|p| p.description())
                .map(|s| s.to_string());
            let rows_empty = section.rows().is_empty();
            *seen.borrow_mut() = Some((
                calm.is_some(),
                error.is_some(),
                icon_name,
                css_classes,
                description,
                rows_empty,
            ));
        },
    );
    let (calm_showing, error_showing, icon_name, css_classes, description, rows_empty) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if calm_showing {
        return Err(
            "the calm \"No ports open\" page must not be showing once the helper is \
                     known to be unreachable"
                .to_string(),
        );
    }
    if !error_showing {
        return Err("an unreachable helper must render its own, distinguishable state".to_string());
    }
    let icon = icon_name.unwrap_or_default();
    if !(icon.contains("error") || icon.contains("warning")) {
        return Err(format!(
            "the unreachable state's icon must read as trouble, unlike the calm state's: {icon:?}"
        ));
    }
    if !css_classes.iter().any(|c| c == "error" || c == "warning") {
        return Err(format!(
            "the unreachable state must carry an error/warning CSS class: {css_classes:?}"
        ));
    }
    match description.as_deref() {
        Some(d) if d.contains("timed out") => {}
        other => {
            return Err(format!(
                "the helper's own reason must be shown, verbatim: {other:?}"
            ))
        }
    }
    if !rows_empty {
        return Err("there must be no rows when the helper could not even be asked".to_string());
    }
    Ok(())
}

/// I5: before any of `set_rules`/`set_unreachable`/`set_errored` has ever
/// been called, this section must not be sitting on the calm "No ports
/// open" claim -- a fresh `OpenNowSection` has not earned the right to
/// state that, and a zbus proxy carries no default per-call timeout to
/// bound how long "brief" would actually be against a hung helper.
fn the_initial_state_before_any_answer_is_neither_calm_nor_populated() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowLoading",
        move |_app| {
            let section = OpenNowSection::with_clock(Box::new(SharedClock::at(BASE_TIME)));
            *seen.borrow_mut() = Some((
                section.loading_note().is_some(),
                section.empty_note().is_some(),
                section.error_note().is_some(),
                section.rows().is_empty(),
            ));
        },
    );
    let (loading, calm, error, rows_empty) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if !loading {
        return Err("a freshly constructed section must show its loading state".to_string());
    }
    if calm {
        return Err(
            "\"No ports open\" must not be the default before anything has been asked".to_string(),
        );
    }
    if error {
        return Err("there is no failure to report yet either".to_string());
    }
    if !rows_empty {
        return Err("there must be no rows before any data has arrived".to_string());
    }
    Ok(())
}

/// I2: a helper that answered with a typed error is a different fact from
/// one that could not be reached at all, and must not share its wording --
/// the same distinction `status_bar.rs`'s own pinned test checks, proven
/// here on the real widget this section actually shows. I4: it also must
/// not claim a refusal the error may not be -- `set_errored` renders the
/// identical error-page state for a `StateStore` failure inside the
/// helper (not a decision anyone made) as it does for a polkit denial.
fn an_errored_reply_reads_differently_from_an_unreachable_helper() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowErrored",
        move |_app| {
            let section = OpenNowSection::with_clock(Box::new(SharedClock::at(BASE_TIME)));
            section.set_errored("not authorized: com.jacopobriccola.Porthole.List");
            let page = section.error_note();
            let title = page.as_ref().map(|p| p.title().to_string());
            let description = page
                .as_ref()
                .and_then(|p| p.description())
                .map(|s| s.to_string());
            *seen.borrow_mut() = Some((title, description));
        },
    );
    let (title, description) = result.borrow_mut().take().ok_or("activation never ran")?;
    let title = title.ok_or("an errored reply must render the error page")?;
    if title.to_lowercase().contains("unreachable") {
        return Err(format!(
            "an errored reply must not be titled as if the helper could not be reached: \
             {title:?}"
        ));
    }
    if title.to_lowercase().contains("refus") || title.to_lowercase().contains("declin") {
        return Err(format!(
            "an errored reply's title must not assert a refusal/decision the error may not \
             be: {title:?}"
        ));
    }
    match description.as_deref() {
        Some(d) if d.contains("not authorized") => {}
        other => {
            return Err(format!(
                "the helper's own error reason must survive verbatim: {other:?}"
            ))
        }
    }
    Ok(())
}

/// I1: a close already in flight when a refresh failure lands must not be
/// able to repaint the calm empty state over the error page once it
/// resolves. `set_unreachable` clears the section's own rule list because
/// that list is unconfirmed once the helper cannot be reached -- but a
/// close started before that failure landed is still out there, unaware,
/// and its own success handler used to recompute "what's left open" from
/// whatever `inner.rules` held *at the time the reply arrived*, not at the
/// time the close was issued. Starting from the list `set_unreachable` had
/// just emptied, that produced an empty "remaining" list and rendered the
/// calm "No ports open" page directly over "Porthole helper unreachable".
/// `simulate_close_succeeded` drives the real close-success code path
/// without needing a live D-Bus reply (see its own doc comment for why the
/// container this test runs in cannot provide one).
fn a_close_resolving_after_a_refresh_failure_does_not_repaint_the_calm_state() -> Result<(), String>
{
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowCloseRaceRefreshFailure",
        move |_app| {
            let section = OpenNowSection::with_clock(Box::new(SharedClock::at(BASE_TIME)));
            let rule = wire_rule(BASE_TIME, 5173, "tcp", "10.10.10.0/24", 3600);
            let id = rule.id.clone();
            section.set_rules(&[rule]);

            // The close is issued here, against the list above -- then,
            // before its reply arrives, a refresh failure lands.
            section.set_unreachable("could not reach the porthole helper: timed out");

            // Only now does the close's reply arrive.
            section.simulate_close_succeeded(&id);

            let calm = section.empty_note();
            let error = section.error_note();
            let error_title = error.as_ref().map(|p| p.title().to_string());
            *seen.borrow_mut() = Some((calm.is_some(), error.is_some(), error_title));
        },
    );
    let (calm_showing, error_showing, error_title) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if calm_showing {
        return Err(
            "the calm \"No ports open\" page must not reappear once a close in flight \
             resolves after a refresh failure already reported the helper unreachable"
                .to_string(),
        );
    }
    if !error_showing {
        return Err(
            "the unreachable state must still be showing after the in-flight close resolves"
                .to_string(),
        );
    }
    match error_title.as_deref() {
        Some(t) if t.contains("unreachable") => {}
        other => {
            return Err(format!(
                "expected the unreachable title to survive the close's resolution, got {other:?}"
            ))
        }
    }
    Ok(())
}

/// The same interleaving again, one layer out: the guard above also decides
/// whether anything is announced. `connect_close_succeeded` hands its
/// callback the list this section re-rendered from, and a close that
/// resolves against a list it was not issued against never reaches that
/// re-render -- so there is no list to hand out, and in particular not the
/// empty one `set_unreachable` left behind, which a caller would read as
/// "nothing is open" and mark its own rows from.
fn a_close_resolving_after_a_refresh_failure_announces_nothing() -> Result<(), String> {
    let announced = Rc::new(RefCell::new(Vec::new()));
    let seen = announced.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowCloseRaceNoAnnouncement",
        move |_app| {
            let section = OpenNowSection::with_clock(Box::new(SharedClock::at(BASE_TIME)));
            let rule = wire_rule(BASE_TIME, 5173, "tcp", "10.10.10.0/24", 3600);
            let id = rule.id.clone();
            section.set_rules(&[rule]);

            let recorded = seen.clone();
            section.connect_close_succeeded(move |remaining| {
                recorded.borrow_mut().push(remaining.to_vec());
            });

            // The close is issued against the list above; a refresh failure
            // lands before its reply does.
            section.set_unreachable("could not reach the porthole helper: timed out");
            section.simulate_close_succeeded(&id);
        },
    );
    let calls = announced.borrow();
    if !calls.is_empty() {
        return Err(format!(
            "a close resolving against a list it was not issued against must announce nothing, \
             got {} call(s): {:?}",
            calls.len(),
            calls
        ));
    }
    Ok(())
}

/// The other half of the same distinction, so the check above cannot pass
/// by the callback never being called at all: an ordinary close, against
/// the list it was issued against, announces exactly what is left.
fn an_ordinary_close_announces_the_rules_that_remain() -> Result<(), String> {
    let announced = Rc::new(RefCell::new(Vec::new()));
    let seen = announced.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowCloseAnnouncement",
        move |_app| {
            let section = OpenNowSection::with_clock(Box::new(SharedClock::at(BASE_TIME)));
            let closed = wire_rule(BASE_TIME, 5173, "tcp", "10.10.10.0/24", 3600);
            let kept = wire_rule(BASE_TIME, 8080, "tcp", "10.10.10.0/24", 3600);
            let id = closed.id.clone();
            section.set_rules(&[closed, kept]);

            let recorded = seen.clone();
            section.connect_close_succeeded(move |remaining| {
                recorded.borrow_mut().push(
                    remaining
                        .iter()
                        .map(|r| r.id.clone())
                        .collect::<Vec<String>>(),
                );
            });

            section.simulate_close_succeeded(&id);
        },
    );
    let calls = announced.borrow();
    match calls.as_slice() {
        [ids] if ids == &["8080/tcp".to_string()] => Ok(()),
        other => Err(format!(
            "a successful close must announce the rules that remain, once, got {other:?}"
        )),
    }
}

/// The confirmed-empty state is one section among several, not a whole
/// view of its own. Measured on the real widget rather than argued from
/// its type: the section is asked how tall it wants to be at the window's
/// own default width, first with nothing open and then holding one rule,
/// and the empty state must not want more room than the section does with
/// something actually in it. A whole-view empty state fails this by a wide
/// margin -- its icon and padding alone are several rows tall -- and what
/// that costs is the rest of the window scrolling out of sight to make
/// room for a sentence.
fn the_confirmed_empty_state_is_no_taller_than_one_rendered_rule() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowEmptyHeight",
        move |_app| {
            let section = OpenNowSection::with_clock(Box::new(SharedClock::at(BASE_TIME)));
            section.set_rules(&[]);
            // `WINDOW_WIDTH_PX` is `PortholeWindow`'s own default width, so
            // the wrapping this measurement sees is the wrapping a user
            // gets.
            let (_, empty, _, _) = section
                .widget()
                .measure(gtk::Orientation::Vertical, WINDOW_WIDTH_PX);
            section.set_rules(&[wire_rule(BASE_TIME, 5173, "tcp", "10.10.10.0/24", 3600)]);
            let (_, one_rule, _, _) = section
                .widget()
                .measure(gtk::Orientation::Vertical, WINDOW_WIDTH_PX);
            let expands = section.widget().compute_expand(gtk::Orientation::Vertical);
            *seen.borrow_mut() = Some((empty, one_rule, expands));
        },
    );
    let (empty, one_rule, expands) = result.borrow_mut().take().ok_or("activation never ran")?;
    if empty > one_rule {
        return Err(format!(
            "the empty state wants {empty}px of height, more than the {one_rule}px this \
             section takes with a rule actually in it -- a section-scaled quiet state \
             cannot cost more room than the content it stands in for"
        ));
    }
    if expands {
        return Err(
            "the empty state claims vertical expansion, which is what pushes every other \
             section down the window"
                .to_string(),
        );
    }
    Ok(())
}

/// One named check, run by `main` below -- see `tests/window.rs`'s own
/// `Case` alias for why this is a type alias rather than spelled out
/// inline (the clippy finding that alias itself fixed there).
type Case = (&'static str, fn() -> Result<(), String>);

fn main() {
    let cases: [Case; 15] = [
        (
            "an_empty_list_is_a_calm_note_not_an_error",
            an_empty_list_is_a_calm_note_not_an_error,
        ),
        (
            "each_rule_shows_port_protocol_target_and_a_close_button",
            each_rule_shows_port_protocol_target_and_a_close_button,
        ),
        (
            "an_anywhere_scoped_rule_is_marked_and_a_subnet_scoped_one_is_not",
            an_anywhere_scoped_rule_is_marked_and_a_subnet_scoped_one_is_not,
        ),
        (
            "the_countdown_is_live_and_counts_down",
            the_countdown_is_live_and_counts_down,
        ),
        (
            "until_reboot_says_so_instead_of_showing_a_countdown",
            until_reboot_says_so_instead_of_showing_a_countdown,
        ),
        (
            "an_expired_rule_states_the_clock_and_claims_no_outcome",
            an_expired_rule_states_the_clock_and_claims_no_outcome,
        ),
        (
            "a_list_read_past_the_deadline_that_still_names_the_rule_reads_differently",
            a_list_read_past_the_deadline_that_still_names_the_rule_reads_differently,
        ),
        (
            "a_passed_deadline_is_reported_once_to_whoever_can_re_read_the_list",
            a_passed_deadline_is_reported_once_to_whoever_can_re_read_the_list,
        ),
        (
            "an_unreachable_helper_does_not_render_as_the_calm_empty_state",
            an_unreachable_helper_does_not_render_as_the_calm_empty_state,
        ),
        (
            "the_initial_state_before_any_answer_is_neither_calm_nor_populated",
            the_initial_state_before_any_answer_is_neither_calm_nor_populated,
        ),
        (
            "an_errored_reply_reads_differently_from_an_unreachable_helper",
            an_errored_reply_reads_differently_from_an_unreachable_helper,
        ),
        (
            "a_close_resolving_after_a_refresh_failure_does_not_repaint_the_calm_state",
            a_close_resolving_after_a_refresh_failure_does_not_repaint_the_calm_state,
        ),
        (
            "a_close_resolving_after_a_refresh_failure_announces_nothing",
            a_close_resolving_after_a_refresh_failure_announces_nothing,
        ),
        (
            "an_ordinary_close_announces_the_rules_that_remain",
            an_ordinary_close_announces_the_rules_that_remain,
        ),
        (
            "the_confirmed_empty_state_is_no_taller_than_one_rendered_rule",
            the_confirmed_empty_state_is_no_taller_than_one_rendered_rule,
        ),
    ];

    let mut any_failed = false;
    for (name, case) in cases {
        match case() {
            Ok(()) => println!("test {name} ... ok"),
            Err(message) => {
                println!("test {name} ... FAILED: {message}");
                any_failed = true;
            }
        }
    }

    if any_failed {
        std::process::exit(1);
    }
}
