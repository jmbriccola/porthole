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
/// something. Checked structurally (the icon name, the CSS classes), not
/// only the title -- a title alone would still pass if a later change added
/// `.add_css_class("error")` or swapped in a warning glyph.
fn an_empty_list_is_a_calm_status_page_not_an_error() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowEmpty",
        move |_app| {
            let section = OpenNowSection::with_clock(Box::new(SharedClock::at(BASE_TIME)));
            section.set_rules(&[]);
            let status = section.status_page();
            let title = status.as_ref().map(|p| p.title().to_string());
            let icon_name = status
                .as_ref()
                .and_then(|p| p.icon_name())
                .map(|s| s.to_string());
            let css_classes: Vec<String> = status
                .as_ref()
                .map(|p| p.css_classes().iter().map(|c| c.to_string()).collect())
                .unwrap_or_default();
            let rows_empty = section.rows().is_empty();
            *seen.borrow_mut() = Some((title, icon_name, css_classes, rows_empty));
        },
    );
    let (title, icon_name, css_classes, rows_empty) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if title.as_deref() != Some("No ports open") {
        return Err(format!(
            "expected a status page titled \"No ports open\", got {title:?}"
        ));
    }
    let icon = icon_name.unwrap_or_default();
    if icon.contains("warning") || icon.contains("error") {
        return Err(format!(
            "the empty state's icon reads as a problem, not the ordinary state it is: {icon:?}"
        ));
    }
    if css_classes.iter().any(|c| c == "error" || c == "warning") {
        return Err(format!(
            "the empty state carries an error/warning CSS class: {css_classes:?}"
        ));
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

/// The other half of the live-countdown property: a rule that still has a
/// few seconds left when the section first renders it must flip to
/// "closing" -- on the real widget, via `refresh()` -- once that time has
/// genuinely passed, rather than ever showing a negative duration.
fn an_expired_rule_reads_as_closing_not_as_a_negative_time() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowExpired",
        move |_app| {
            let clock = SharedClock::at(BASE_TIME);
            let section = OpenNowSection::with_clock(Box::new(clock.clone()));
            // 65s lifetime, opened 60s before BASE_TIME: 5 seconds left as
            // of BASE_TIME, still a normal countdown at construction.
            section.set_rules(&[wire_rule(BASE_TIME, 5173, "tcp", "10.10.10.0/24", 65)]);
            clock.advance_to(BASE_TIME + 65);
            section.refresh();
            *seen.borrow_mut() = Some(section.countdown_text(0));
        },
    );
    let text = result.borrow_mut().take().ok_or("activation never ran")?;
    if text != "closing" {
        return Err(format!("expected \"closing\", got {text:?}"));
    }
    Ok(())
}

/// Task 6's own case: a failure to reach the helper must not render as
/// "No ports open" -- see `src/open_now.rs`'s own module doc for why
/// conflating "confirmed nothing is open" with "could not ask" is this
/// project's characteristic defect. Checked structurally (icon, CSS
/// classes, and that the calm page is genuinely gone, not merely covered),
/// the same way `an_empty_list_is_a_calm_status_page_not_an_error` checks
/// the calm state's own icon/CSS rather than only its title.
fn an_unreachable_helper_does_not_render_as_the_calm_empty_state() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowUnreachable",
        move |_app| {
            let section = OpenNowSection::with_clock(Box::new(SharedClock::at(BASE_TIME)));
            section.set_unreachable("could not reach the porthole helper: timed out");
            let calm = section.status_page();
            let error = section.error_page();
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

/// One named check, run by `main` below -- see `tests/window.rs`'s own
/// `Case` alias for why this is a type alias rather than spelled out
/// inline (the clippy finding that alias itself fixed there).
type Case = (&'static str, fn() -> Result<(), String>);

fn main() {
    let cases: [Case; 6] = [
        (
            "an_empty_list_is_a_calm_status_page_not_an_error",
            an_empty_list_is_a_calm_status_page_not_an_error,
        ),
        (
            "each_rule_shows_port_protocol_target_and_a_close_button",
            each_rule_shows_port_protocol_target_and_a_close_button,
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
            "an_expired_rule_reads_as_closing_not_as_a_negative_time",
            an_expired_rule_reads_as_closing_not_as_a_negative_time,
        ),
        (
            "an_unreachable_helper_does_not_render_as_the_calm_empty_state",
            an_unreachable_helper_does_not_render_as_the_calm_empty_state,
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
