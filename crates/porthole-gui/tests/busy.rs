//! What the window shows while it is waiting for the helper, and -- the
//! half that matters more -- what it stops showing afterwards.
//!
//! Its own `[[test]]` target for the reason every GTK-touching file in this
//! crate is one: see `tests/window.rs`'s module doc. `harness = false`, so
//! `main` runs the checks below in sequence on this process's one real main
//! thread.
//!
//! These are the checks that need real time to pass. `crate::busy` arms a
//! `glib::timeout_add_local_once`, so "nothing appeared" and "something
//! appeared" are only distinguishable by draining the main context across
//! the delay -- which is exactly what [`pump_for`] does, at the cost of
//! about two seconds for the whole file.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use adw::prelude::*;
use porthole_gui::busy::{BusyIndicator, BUSY_DELAY};

/// Runs `f` inside a real `adw::Application` activation -- the same helper
/// every other GTK-touching test file here carries, for the same reason:
/// widgets cannot be built before `gtk_init`, which activation performs.
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

/// Drains the main context for `duration` of real wall clock, so any
/// `glib` timeout due inside that window actually fires. Unlike the
/// `pump_until` the other files use, this one has no condition to stop
/// early on: half of what is checked here is that something *did not*
/// happen, and that can only be established by waiting past the moment it
/// would have.
fn pump_for(duration: Duration) {
    let context = gtk::glib::MainContext::default();
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        while context.iteration(false) {}
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Comfortably past [`BUSY_DELAY`], so "it never appeared" is a fact about
/// the delay having elapsed rather than about the test being impatient.
fn past_the_delay() -> Duration {
    BUSY_DELAY + Duration::from_millis(400)
}

/// How long a helper that answers straight away takes -- the case the
/// delay exists for. Long enough that the main context really does iterate
/// while the operation is outstanding, so a "delay" that defers to the next
/// iteration and no further is caught here rather than passing by accident.
const A_FAST_ANSWER: Duration = Duration::from_millis(50);

/// The anti-flicker property, and the whole reason for the delay: an
/// operation the helper answers immediately must put nothing on screen at
/// all. A spinner that appears and vanishes inside a tenth of a second
/// draws the eye to something already over, which is worse than the
/// motionless window this was added to repair.
///
/// Checked twice over: nothing is showing while an operation as short as a
/// helper answering straight away is outstanding -- with the main context
/// running throughout, so a timer that merely defers to the next iteration
/// would be caught -- and nothing is showing after the delay has gone by
/// with the operation long finished, which is what catches a timer that was
/// armed and never cancelled.
fn an_operation_that_finishes_quickly_shows_nothing_at_all() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.BusyNoFlash",
        move |_app| {
            let indicator = BusyIndicator::new();
            let busy = indicator.begin();
            // Outstanding for as long as a helper that answers straight
            // away takes, with the main context running through all of it.
            pump_for(A_FAST_ANSWER);
            let showing_while_waiting = indicator.is_showing();
            drop(busy);
            // Past the point the spinner would have appeared, had the
            // operation still been outstanding.
            pump_for(past_the_delay());
            *seen.borrow_mut() = Some((
                showing_while_waiting,
                indicator.is_showing(),
                indicator.is_busy(),
            ));
        },
    );
    let (showing_while_waiting, showing_after, still_busy) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if showing_while_waiting {
        return Err(
            "the spinner appeared while a call the helper answers straight away was still \
             outstanding, so a fast open produces a visible flicker"
                .to_string(),
        );
    }
    if showing_after {
        return Err(
            "the spinner appeared after the operation had already finished: the pending \
             timer outlived the operation that armed it"
                .to_string(),
        );
    }
    if still_busy {
        return Err("the indicator still reports an outstanding operation".to_string());
    }
    Ok(())
}

/// The other half: an operation that really is slow does say so, and stops
/// saying it the moment it ends. Without this the delay above could be
/// satisfied by never showing anything.
fn an_operation_that_outlives_the_delay_says_so_and_stops_when_it_ends() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate("com.jacopobriccola.Porthole.Test.BusyShows", move |_app| {
        let indicator = BusyIndicator::new();
        let busy = indicator.begin();
        pump_for(past_the_delay());
        let showing_while_waiting = indicator.is_showing();
        drop(busy);
        let showing_after = indicator.is_showing();
        *seen.borrow_mut() = Some((showing_while_waiting, showing_after, indicator.is_busy()));
    });
    let (showing_while_waiting, showing_after, still_busy) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if !showing_while_waiting {
        return Err(
            "an operation outstanding well past the delay put nothing on screen, so a slow \
             open still looks like a frozen window"
                .to_string(),
        );
    }
    if showing_after {
        return Err("the spinner went on turning after the operation ended".to_string());
    }
    if still_busy {
        return Err("the indicator still reports an outstanding operation".to_string());
    }
    Ok(())
}

/// The control that started the operation cannot start a second one while
/// the first is unanswered -- and gets itself back afterwards. Not delayed,
/// unlike the spinner: this is not a claim about progress, it is what stops
/// a double press sending a second request.
fn the_control_is_held_until_the_operation_ends() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.BusyDisable",
        move |_app| {
            let indicator = BusyIndicator::new();
            let button = gtk::Button::with_label("Open");
            indicator.disable_while_busy(&button);
            let before = button.is_sensitive();
            let busy = indicator.begin();
            let during = button.is_sensitive();
            drop(busy);
            *seen.borrow_mut() = Some((before, during, button.is_sensitive()));
        },
    );
    let (before, during, after) = result.borrow_mut().take().ok_or("activation never ran")?;
    if !before {
        return Err("registering a control must not desensitise it on its own".to_string());
    }
    if during {
        return Err(
            "the control stayed pressable while porthole was waiting, so a second press \
             sends a second request"
                .to_string(),
        );
    }
    if !after {
        return Err("the control never came back after the operation ended".to_string());
    }
    Ok(())
}

/// Two operations sharing one indicator -- a refresh landing on top of
/// another, which `schedule_refresh` allows -- must not have the first to
/// finish take the indication away from the second.
fn the_last_operation_to_finish_is_what_clears_it() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.BusyOverlap",
        move |_app| {
            let indicator = BusyIndicator::new();
            let first = indicator.begin();
            let second = indicator.begin();
            pump_for(past_the_delay());
            let showing_with_both = indicator.is_showing();
            drop(first);
            let showing_with_one = indicator.is_showing();
            drop(second);
            *seen.borrow_mut() =
                Some((showing_with_both, showing_with_one, indicator.is_showing()));
        },
    );
    let (with_both, with_one, with_none) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if !with_both || !with_one {
        return Err(format!(
            "the first operation to finish took the indication away from the one still \
             outstanding: showing with both {with_both}, with one {with_one}"
        ));
    }
    if with_none {
        return Err("the indication outlived the last outstanding operation".to_string());
    }
    Ok(())
}

/// One named check, run by `main` below -- see `tests/window.rs`'s own
/// `Case` alias for why this is a type alias.
type Case = (&'static str, fn() -> Result<(), String>);

fn main() {
    let cases: [Case; 4] = [
        (
            "an_operation_that_finishes_quickly_shows_nothing_at_all",
            an_operation_that_finishes_quickly_shows_nothing_at_all,
        ),
        (
            "an_operation_that_outlives_the_delay_says_so_and_stops_when_it_ends",
            an_operation_that_outlives_the_delay_says_so_and_stops_when_it_ends,
        ),
        (
            "the_control_is_held_until_the_operation_ends",
            the_control_is_held_until_the_operation_ends,
        ),
        (
            "the_last_operation_to_finish_is_what_clears_it",
            the_last_operation_to_finish_is_what_clears_it,
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
