//! Runs a real `PortholeWindow` under Xvfb and asserts on the real widget.
//!
//! `harness = false` (see `Cargo.toml`): gtk4-rs asserts that every GTK call
//! in a process comes from whichever OS thread made the very first one, and
//! that assertion does not care whether the first thread has since exited --
//! it just rejects any call from a different thread, forever, for the rest
//! of the process. Cargo's normal test harness spawns a fresh OS thread per
//! `#[test]` function, even under `--test-threads=1`, so two ordinary tests
//! that each touch GTK abort the second one with "GTK may only be used from
//! the main thread" -- confirmed empirically before writing this file, not
//! assumed. A plain `fn main()` keeps every check on the one real thread a
//! normal process actually runs on.
//!
//! Each `[[test]]` target is its own process, so this is not a limit on how
//! many GTK-touching checks the whole crate can have -- only on how many can
//! share *this* file. A later task adding a new section adds its own
//! `tests/<name>.rs` with the same `harness = false` shape, rather than
//! adding more cases here.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use porthole_gui::window::PortholeWindow;

/// Runs `f` inside a real `adw::Application` activation, on a session bus
/// `dbus-run-session` provides (see `tests/container/gui-test.sh`) -- the
/// same activation path production code goes through, not a bare widget
/// tree assembled with no application at all.
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

/// The distinction is the whole point of this harness. A widget tree built
/// in memory proves nothing about whether GTK could lay it out; a realized
/// window proves the tests are exercising the real toolkit. If this ever
/// regresses to constructing-without-realizing, every later test in this
/// milestone quietly stops testing anything.
fn the_window_is_actually_realized_not_merely_constructed() -> Result<(), String> {
    let realized = Rc::new(Cell::new(false));
    let seen = realized.clone();
    activate("com.jacopobriccola.Porthole.Test.Realized", move |app| {
        let win = PortholeWindow::new(app);
        win.present();
        seen.set(win.is_realized());
    });
    if realized.get() {
        Ok(())
    } else {
        Err("the window must really be created".to_string())
    }
}

/// The other half of the same distinction, kept as a standing check rather
/// than only a one-off manual demonstration: a window that is constructed
/// but never `present()`-ed must **not** read back as realized. If it did,
/// the test above would no longer be capable of catching the regression it
/// exists to catch.
fn a_window_that_is_never_presented_is_not_realized() -> Result<(), String> {
    let realized = Rc::new(Cell::new(true));
    let seen = realized.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.NotPresented",
        move |app| {
            let win = PortholeWindow::new(app);
            // Deliberately no win.present() here.
            seen.set(win.is_realized());
        },
    );
    if !realized.get() {
        Ok(())
    } else {
        Err("a window that was never presented read back as realized".to_string())
    }
}

/// Runs the pending GLib main-context iterations, so GTK's layout pass --
/// and with it, the breakpoint evaluation that pass includes -- actually
/// happens before a test reads the result back. `present()` on its own is
/// not enough: measured directly in a container, a window built already
/// narrow and then `present()`-ed with no pump afterwards still reports
/// `current_breakpoint() == None` -- the layout pass that would apply the
/// breakpoint simply had not run yet.
fn pump_main_context() {
    let context = gtk::glib::MainContext::default();
    for _ in 0..50 {
        while context.iteration(false) {}
    }
}

/// `AdwBreakpoint` is a spec requirement, and a breakpoint that was never
/// added silently does nothing -- the window just gets cramped. This does
/// not merely check that a `Breakpoint` object exists somewhere in
/// `PortholeWindow`: that would pass even if `add_breakpoint` were never
/// called, since the object is constructed either way. Instead it presents a
/// real window **already sized** narrower than the threshold (resizing
/// *after* `present()` is unreliable -- see the module doc comment on
/// `window.rs`) and reads `current_breakpoint()` back from the window
/// itself -- the property libadwaita only populates once a registered
/// breakpoint's condition actually matches the window's real geometry -- and
/// checks it is the exact breakpoint `PortholeWindow` registered, not merely
/// present.
fn the_window_is_usable_at_a_narrow_width() -> Result<(), String> {
    let ok = Rc::new(Cell::new(false));
    let seen = ok.clone();
    activate("com.jacopobriccola.Porthole.Test.Breakpoint", move |app| {
        let win = PortholeWindow::new(app);
        win.set_default_size(300, 600); // narrower than the 400px threshold
        win.present();
        pump_main_context();
        seen.set(win.current_breakpoint().as_ref() == Some(win.breakpoint()));
    });
    if ok.get() {
        Ok(())
    } else {
        Err("no breakpoint applied to a window narrower than 400px".to_string())
    }
}

/// The other half of the same check: at the window's ordinary width, the
/// narrow breakpoint must **not** be the current one. Without this, the test
/// above could not tell a breakpoint that is genuinely conditional on width
/// apart from one that is simply always applied.
fn an_ordinary_width_window_does_not_trigger_the_narrow_breakpoint() -> Result<(), String> {
    let ok = Rc::new(Cell::new(false));
    let seen = ok.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.BreakpointControl",
        move |app| {
            let win = PortholeWindow::new(app);
            win.present();
            pump_main_context();
            seen.set(win.current_breakpoint().is_none());
        },
    );
    if ok.get() {
        Ok(())
    } else {
        Err("the narrow breakpoint applied at the window's ordinary width".to_string())
    }
}

/// `PortholeWindow::new` alone is not what a user runs -- `app::build`'s own
/// `connect_activate` closure is, and it is the one place that could forget
/// to call `.present()` in the actual production path. This exercises that
/// exact closure rather than only a hand-assembled window.
fn applications_own_activation_handler_also_realizes_a_window() -> Result<(), String> {
    let app = porthole_gui::app::build();
    let realized = Rc::new(Cell::new(false));
    let seen = realized.clone();
    // Chain onto app::build()'s own activate handler rather than replacing
    // it, so this observes what production activation actually does.
    app.connect_activate(move |app| {
        if let Some(win) = app.active_window().and_downcast::<adw::ApplicationWindow>() {
            seen.set(win.is_realized());
        }
        app.quit();
    });
    app.run_with_args::<&str>(&[]);
    if realized.get() {
        Ok(())
    } else {
        Err("app::build()'s own activation handler did not realize a window".to_string())
    }
}

/// Task 5's header-bar affordance: structural presence and the right
/// tooltip, plus keyboard reachability -- not a simulated click. A click's
/// own behaviour (a fresh `OpenDialog` presented over the window) is real
/// code, exercised by `tests/open_dialog.rs` for what it builds and sends,
/// but not proven end-to-end from this button press; see `window.rs`'s own
/// comment on the click handler for why.
fn the_window_has_an_open_button_that_is_reachable_from_the_keyboard() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate("com.jacopobriccola.Porthole.Test.OpenButton", move |app| {
        let win = PortholeWindow::new(app);
        win.present();
        let button = win.open_button();
        seen.replace(Some((
            button.tooltip_text().map(|s| s.to_string()),
            button.is_focusable(),
        )));
    });
    let (tooltip, focusable) = result.borrow_mut().take().ok_or("activation never ran")?;
    if tooltip.as_deref() != Some("Open a port") {
        return Err(format!("expected tooltip \"Open a port\", got {tooltip:?}"));
    }
    if !focusable {
        return Err("the open button must be reachable by keyboard".to_string());
    }
    Ok(())
}

/// One named check, run by `main` below. A type alias rather than spelling
/// `(&str, fn() -> Result<(), String>)` out at the call site: clippy's
/// `type_complexity` flagged the inline form (the actual finding from the
/// milestone's first clippy pass over this crate -- `useless_vec` was a
/// plausible guess at review time, but checked directly, it did not fire
/// here even before this alias existed).
type Case = (&'static str, fn() -> Result<(), String>);

fn main() {
    // A plain array, not `vec![]`: the list is fixed at compile time and
    // never grows, so there is nothing a `Vec` buys here, independently of
    // what clippy does or does not flag.
    let cases: [Case; 6] = [
        (
            "the_window_is_actually_realized_not_merely_constructed",
            the_window_is_actually_realized_not_merely_constructed,
        ),
        (
            "a_window_that_is_never_presented_is_not_realized",
            a_window_that_is_never_presented_is_not_realized,
        ),
        (
            "the_window_is_usable_at_a_narrow_width",
            the_window_is_usable_at_a_narrow_width,
        ),
        (
            "an_ordinary_width_window_does_not_trigger_the_narrow_breakpoint",
            an_ordinary_width_window_does_not_trigger_the_narrow_breakpoint,
        ),
        (
            "applications_own_activation_handler_also_realizes_a_window",
            applications_own_activation_handler_also_realizes_a_window,
        ),
        (
            "the_window_has_an_open_button_that_is_reachable_from_the_keyboard",
            the_window_has_an_open_button_that_is_reachable_from_the_keyboard,
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
