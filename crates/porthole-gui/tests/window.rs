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
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use adw::prelude::*;
use porthole_core::ipc::WireRule;
use porthole_core::listening::{Binding, Service};
use porthole_core::model::Protocol;
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

/// Like `pump_main_context`, but for waiting on genuinely asynchronous
/// work (a D-Bus round trip's own connect attempt) rather than a single
/// layout pass: `iteration(false)` alone only drains what is *already*
/// pending, and a connection attempt's completion can arrive from a
/// background thread after this function has already found nothing
/// pending. Retries on a short sleep instead of blocking on
/// `iteration(true)`, which could in principle wait forever if nothing
/// ever wakes it -- this always returns within `timeout`, condition met or
/// not, so a stuck async path fails the test rather than hanging the
/// process.
fn pump_until(condition: impl Fn() -> bool, timeout: Duration) -> bool {
    let context = gtk::glib::MainContext::default();
    let deadline = Instant::now() + timeout;
    loop {
        while context.iteration(false) {}
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return condition();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A rule as the wire reports it -- just enough to give
/// `every_action_is_reachable_from_the_keyboard` a real close button to
/// check, the same shape `tests/open_now.rs`'s own `wire_rule` fixture
/// uses.
fn wire_rule_fixture() -> WireRule {
    WireRule {
        id: "5173/tcp".to_string(),
        port: 5173,
        protocol: "tcp".to_string(),
        target: "10.10.10.0/24".to_string(),
        scope: "network".to_string(),
        backend: "firewalld".to_string(),
        opened_at: 1_757_100_000,
        expires_at: 1_757_103_600,
        uid: 1000,
    }
}

/// A service as `porthole_core::listening::scan` would produce one --
/// network-facing, so it gets a real, focusable Open button, the same
/// shape `tests/listening.rs`'s own `svc` fixture uses.
fn listening_service_fixture() -> Service {
    Service {
        port: 5173,
        protocol: Protocol::Tcp,
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        binding: Binding::AllInterfaces,
        process: Some("node".to_string()),
        pid: None,
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

/// Task 6's own check: every action a click can reach must also be
/// reachable from the keyboard -- a GNOME app that needs a mouse is not a
/// GNOME app. Populates both sections with real fixture data first (via
/// the same public setters `window.rs`'s own `refresh` calls), since an
/// empty window only has the header button to check; `actionable_widgets`
/// is a structural readback of the real, currently-rendered buttons, so
/// this is asserting focusability on the exact widgets a user would tab
/// through, not a hand-maintained list of what should be there.
fn every_action_is_reachable_from_the_keyboard() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate("com.jacopobriccola.Porthole.Test.Keyboard", move |app| {
        let win = PortholeWindow::new(app);
        win.open_now().set_rules(&[wire_rule_fixture()]);
        win.listening().set_services(&[listening_service_fixture()]);
        win.present();
        let flags: Vec<bool> = win
            .actionable_widgets()
            .iter()
            .map(|w| w.is_focusable())
            .collect();
        seen.replace(Some(flags));
    });
    let flags = result.borrow_mut().take().ok_or("activation never ran")?;
    // The header button, one "Open now" close button, one "Listening" Open
    // button: proof the fixtures above actually produced rows to check,
    // not just the one widget an empty window would have had anyway.
    if flags.len() < 3 {
        return Err(format!(
            "expected at least 3 actionable widgets (header button + one row from each \
             section), got {}",
            flags.len()
        ));
    }
    if let Some(index) = flags.iter().position(|focusable| !focusable) {
        return Err(format!(
            "actionable widget at index {index} cannot be reached by keyboard"
        ));
    }
    Ok(())
}

/// `AdwBreakpoint` is a spec requirement, and a registered breakpoint with
/// no `Breakpoint::add_setter`/`add_setters` attached activates and
/// changes nothing -- the window simply becomes cramped, which no test
/// notices unless it asks something a bare `current_breakpoint()` check
/// cannot answer: not just "did the breakpoint apply" (already proven by
/// `the_window_is_usable_at_a_narrow_width` above) but "did applying it
/// actually change the layout". This presents a real, really narrow window
/// -- the same sequence that test uses -- and reads back `content`'s own,
/// real margin, which `PortholeWindow::new` registers a setter to shrink
/// while the breakpoint matches.
fn a_narrow_window_shrinks_its_margins_so_every_row_stays_readable() -> Result<(), String> {
    let result = Rc::new(Cell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.BreakpointMargins",
        move |app| {
            let win = PortholeWindow::new(app);
            win.set_default_size(300, 600); // narrower than the 400px threshold
            win.present();
            pump_main_context();
            seen.set(Some(win.content().margin_top()));
        },
    );
    match result.get() {
        Some(12) => Ok(()),
        Some(other) => Err(format!(
            "expected the narrow-width margin (12px) to have applied, got {other}px -- either \
             the breakpoint did not match or its setter did not run"
        )),
        None => Err("activation never ran".to_string()),
    }
}

/// The other half: at the window's ordinary width, `content`'s margin must
/// stay at its ordinary 24px -- without this, the test above could not
/// tell a margin that is genuinely conditional on the breakpoint apart
/// from one simply set to 12px unconditionally at construction.
fn an_ordinary_width_window_keeps_its_ordinary_margins() -> Result<(), String> {
    let result = Rc::new(Cell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.BreakpointMarginsControl",
        move |app| {
            let win = PortholeWindow::new(app);
            win.present();
            pump_main_context();
            seen.set(Some(win.content().margin_top()));
        },
    );
    match result.get() {
        Some(24) => Ok(()),
        Some(other) => Err(format!(
            "expected the ordinary 24px margin at ordinary width, got {other}px"
        )),
        None => Err("activation never ran".to_string()),
    }
}

/// The planning defect task 6 exists to repair, proven the strongest way
/// available: a real `PortholeWindow::new`, in this milestone's own test
/// container, which has no live `porthole-helper` and -- unlike the
/// session bus `dbus-run-session` provides for `adw::Application`'s own
/// identity -- no **system** bus either (see `Containerfile.gui`: it
/// installs `dbus-daemon` but nothing here ever starts a system instance
/// of it). So the construction's own initial `refresh`, which reaches the
/// helper over the system bus (`window.rs`'s own module doc explains why),
/// genuinely fails here -- this is the real failure path running, not a
/// substitute for it. `pump_until` (bounded, never blocks indefinitely)
/// waits for that failure to propagate all the way to `OpenNowSection`'s
/// own rendered state and the status line.
///
/// This is also the one place in this crate proving the distinction this
/// task exists to draw: a window that could not reach the helper must
/// **not** show the same calm "No ports open" page a window that
/// genuinely has nothing open would.
fn a_construction_with_an_unreachable_helper_does_not_show_the_calm_empty_state(
) -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.UnreachableConstruction",
        move |app| {
            let win = PortholeWindow::new(app);
            win.present();
            let settled = pump_until(
                || win.open_now().status_page().is_none() && win.open_now().error_page().is_some(),
                Duration::from_secs(5),
            );
            let calm_showing = win.open_now().status_page().is_some();
            let error_showing = win.open_now().error_page().is_some();
            let status_bar_prominent = win.status_bar().is_prominent();
            seen.replace(Some((
                settled,
                calm_showing,
                error_showing,
                status_bar_prominent,
            )));
        },
    );
    let (settled, calm_showing, error_showing, status_bar_prominent) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if !settled {
        return Err(
            "the helper-unreachable state never settled within the timeout -- see this \
             test's own comment on why the container has no system bus to fail against"
                .to_string(),
        );
    }
    if calm_showing {
        return Err(
            "a window constructed with no reachable helper must not show the calm \"No ports \
             open\" page"
                .to_string(),
        );
    }
    if !error_showing {
        return Err(
            "a window constructed with no reachable helper must show its own, distinguishable \
             state"
                .to_string(),
        );
    }
    if !status_bar_prominent {
        return Err(
            "the status line must say, prominently, that the helper could not be reached"
                .to_string(),
        );
    }
    Ok(())
}

/// Presses a "Listening" row's own Open button -- `emit_clicked`, the real
/// signal a pointer or the keyboard would emit -- and reads back the one
/// thing pressing it is supposed to produce: the open dialog, on this
/// window, as `AdwApplicationWindow::visible_dialog` reports it.
///
/// This crate's other checks on that button all stop at
/// `open_button_for(index).is_some()` and `activate_open(index)`, which
/// `listening_section.rs` documents as a pure lookup rather than a
/// simulated click. Presence was covered; pressing was not, and a button
/// with no handler passes every one of them. A user on Fedora
/// Workstation found the difference: the button did nothing at all.
fn pressing_a_listening_rows_open_button_opens_the_dialog() -> Result<(), String> {
    let opened = Rc::new(Cell::new(false));
    let seen = opened.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.RowOpenButtonClick",
        move |app| {
            let win = PortholeWindow::new(app);
            win.present();
            win.listening().set_services(&[listening_service_fixture()]);
            let Some(button) = win.listening().open_button_for(0) else {
                return;
            };
            button.emit_clicked();
            pump_main_context();
            seen.set(win.visible_dialog().is_some());
        },
    );
    if opened.get() {
        Ok(())
    } else {
        Err("pressing a Listening row's Open button presented no dialog".to_string())
    }
}

/// The same press, after the answer about Docker has landed.
///
/// That answer arrives on every launch -- a list of published ports, or
/// the fact that none could be had -- and it rebuilds this section's rows.
/// A row's Open button therefore has to survive a rebuild that no part of
/// the open flow asked for. It did not: the button was dead in every
/// installed copy of porthole, because the handler was attached from
/// outside the rebuild.
fn a_rows_open_button_survives_the_docker_answer() -> Result<(), String> {
    let opened = Rc::new(Cell::new(false));
    let seen = opened.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.RowOpenButtonAfterDocker",
        move |app| {
            let win = PortholeWindow::new(app);
            win.present();
            win.listening().set_services(&[listening_service_fixture()]);
            // Both ways that answer can come back, one after the other:
            // neither may cost the row its button's handler.
            win.listening().set_docker_ports(&[]);
            win.listening().set_docker_unavailable();
            let Some(button) = win.listening().open_button_for(0) else {
                return;
            };
            button.emit_clicked();
            pump_main_context();
            seen.set(win.visible_dialog().is_some());
        },
    );
    if opened.get() {
        Ok(())
    } else {
        Err(
            "pressing a Listening row's Open button after the Docker answer presented no dialog"
                .to_string(),
        )
    }
}

/// The round trip a person actually made on a Fedora Workstation VM: open a
/// port from a "Listening" row, then close it again from "Open now", and
/// find the row's Open button back where it was.
///
/// Both buttons are pressed for real -- `emit_clicked` on the widgets the
/// window itself built, not a setter standing in for a press. The one thing
/// this container cannot supply is the close's own reply: `close_by_id`
/// goes out over the system bus, and there is no system bus here (see
/// `a_construction_with_an_unreachable_helper_does_not_show_the_calm_empty_state`
/// above), so the reply arrives through `simulate_close_succeeded`, which
/// `open_now.rs` documents as the seam onto the same close-success path the
/// button's own `Ok(())` arm takes.
///
/// `new_without_initial_load`, not `new`: the initial load calls the same
/// two setters this check drives -- `set_services` from the `/proc` scan,
/// `set_open_ports`/`set_open_ports_unknown` from the helper round trip --
/// and lands them whenever they land. This constructor starts neither, so
/// the calls reaching these two sections are this check's own. (Both
/// constructors were measured against the code that had the defect; both
/// failed this check, so the choice buys determinism here, not the
/// failure.)
fn closing_a_port_brings_back_the_listening_rows_open_button() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.CloseRestoresOpenButton",
        move |app| {
            let win = PortholeWindow::new_without_initial_load(app);
            win.present();
            win.listening().set_services(&[listening_service_fixture()]);

            // Open, from the row itself.
            let Some(open_button) = win.listening().open_button_for(0) else {
                return;
            };
            open_button.emit_clicked();
            pump_main_context();
            let dialog_opened = win.visible_dialog().is_some();
            if let Some(dialog) = win.visible_dialog() {
                dialog.close();
            }
            pump_main_context();

            // What a successful open leaves on screen: `refresh`'s own two
            // calls, the rule list and the ports derived from it.
            let rule = wire_rule_fixture();
            win.open_now().set_rules(std::slice::from_ref(&rule));
            win.listening().set_open_ports(&[rule.port]);
            let button_withheld = win.listening().open_button_for(0).is_none();

            // Close, from the "Open now" row itself.
            let Some(close_button) = win.open_now().close_button_for(0) else {
                return;
            };
            close_button.emit_clicked();
            pump_main_context();
            win.open_now().simulate_close_succeeded(&rule.id);
            pump_main_context();

            let button_back = win.listening().open_button_for(0).is_some();
            *seen.borrow_mut() = Some((dialog_opened, button_withheld, button_back));
        },
    );
    let (dialog_opened, button_withheld, button_back) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if !dialog_opened {
        return Err("pressing the Listening row's Open button presented no dialog".to_string());
    }
    if !button_withheld {
        return Err(
            "a port reported open must leave its Listening row without an Open button, or this \
             check cannot tell the button coming back from its never having gone"
                .to_string(),
        );
    }
    if !button_back {
        return Err(
            "closing the port from \"Open now\" left the Listening row still showing it as open, \
             with no way to open it again"
                .to_string(),
        );
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
    let cases: [Case; 13] = [
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
        (
            "every_action_is_reachable_from_the_keyboard",
            every_action_is_reachable_from_the_keyboard,
        ),
        (
            "a_narrow_window_shrinks_its_margins_so_every_row_stays_readable",
            a_narrow_window_shrinks_its_margins_so_every_row_stays_readable,
        ),
        (
            "an_ordinary_width_window_keeps_its_ordinary_margins",
            an_ordinary_width_window_keeps_its_ordinary_margins,
        ),
        (
            "a_construction_with_an_unreachable_helper_does_not_show_the_calm_empty_state",
            a_construction_with_an_unreachable_helper_does_not_show_the_calm_empty_state,
        ),
        (
            "pressing_a_listening_rows_open_button_opens_the_dialog",
            pressing_a_listening_rows_open_button_opens_the_dialog,
        ),
        (
            "a_rows_open_button_survives_the_docker_answer",
            a_rows_open_button_survives_the_docker_answer,
        ),
        (
            "closing_a_port_brings_back_the_listening_rows_open_button",
            closing_a_port_brings_back_the_listening_rows_open_button,
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
