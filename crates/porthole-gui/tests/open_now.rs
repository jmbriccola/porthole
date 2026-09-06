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
//! presence, computed countdown text), none of which need a GTK layout
//! pass to become true -- only construction, which does need to happen
//! inside a real activation (GTK widgets cannot be built before
//! `gtk_init`, which activation performs).

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use porthole_core::clock::{Clock, SystemClock};
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

/// This fixture's own "now": the same real clock `OpenNowSection` reads by
/// default, before any `tick_at` call ever freezes it. A fixed constant
/// would not agree with that default -- `OpenNowSection` cannot know at
/// construction time what a fixed test constant is going to be -- so the
/// fixture has to read the real clock too.
fn now() -> u64 {
    SystemClock.now()
}

/// A rule as the wire reports it, opened one minute before `now()` with a
/// total lifetime of `lifetime_secs` -- so a 3600s (one hour) rule already
/// has 59 minutes left by the time a test's very first `countdown_text`
/// call reads it, rather than the full hour a rule just opened would show.
/// `lifetime_secs == 0` is the wire's own until-reboot sentinel and is
/// passed straight through as `expires_at == 0`, never offset.
fn wire_rule(port: u16, protocol: &str, target: &str, lifetime_secs: u64) -> WireRule {
    let opened_at = now() - 60;
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
/// something.
fn an_empty_list_is_a_calm_status_page_not_an_error() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowEmpty",
        move |_app| {
            let section = OpenNowSection::new();
            section.set_rules(&[]);
            let status_title = section.status_page().map(|p| p.title().to_string());
            let rows_empty = section.rows().is_empty();
            *seen.borrow_mut() = Some((status_title, rows_empty));
        },
    );
    let (status_title, rows_empty) = result.borrow_mut().take().ok_or("activation never ran")?;
    if status_title.as_deref() != Some("No ports open") {
        return Err(format!(
            "expected a status page titled \"No ports open\", got {status_title:?}"
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
        let section = OpenNowSection::new();
        section.set_rules(&[wire_rule(5173, "tcp", "10.10.10.0/24", 3600)]);
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
/// states a specific remaining time, confidently, and is wrong. `tick_at`
/// is what lets this test observe a genuine second tick with no sleep.
fn the_countdown_is_live_and_counts_down() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowCountdown",
        move |_app| {
            let section = OpenNowSection::new();
            section.set_rules(&[wire_rule(5173, "tcp", "10.10.10.0/24", 3600)]);
            let first = section.countdown_text(0);
            section.tick_at(now() + 61);
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
            let section = OpenNowSection::new();
            section.set_rules(&[wire_rule(5173, "tcp", "10.10.10.0/24", 0)]);
            *seen.borrow_mut() = Some(section.countdown_text(0));
        },
    );
    let text = result.borrow_mut().take().ok_or("activation never ran")?;
    if text != "until reboot" {
        return Err(format!("expected \"until reboot\", got {text:?}"));
    }
    Ok(())
}

fn an_expired_rule_reads_as_closing_not_as_a_negative_time() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.OpenNowExpired",
        move |_app| {
            let section = OpenNowSection::new();
            section.set_rules(&[wire_rule(5173, "tcp", "10.10.10.0/24", 10)]);
            section.tick_at(now() + 60);
            *seen.borrow_mut() = Some(section.countdown_text(0));
        },
    );
    let text = result.borrow_mut().take().ok_or("activation never ran")?;
    if text != "closing" {
        return Err(format!("expected \"closing\", got {text:?}"));
    }
    Ok(())
}

/// One named check, run by `main` below -- see `tests/window.rs`'s own
/// `Case` alias for why this is a type alias rather than spelled out
/// inline (the clippy finding that alias itself fixed there).
type Case = (&'static str, fn() -> Result<(), String>);

fn main() {
    let cases: [Case; 5] = [
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
