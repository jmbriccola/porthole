//! Runs a real `StatusBar` inside an activated `adw::Application`, the same
//! way `tests/window.rs`, `tests/open_now.rs`, `tests/listening.rs` and
//! `tests/open_dialog.rs` do and for the identical reason: `harness = false`
//! (see `Cargo.toml`) because cargo's normal test harness spawns each
//! `#[test]` function on its own OS thread, and gtk4-rs locks GTK to
//! whichever thread makes its first call -- a second GTK-touching test
//! thread wedges the whole process. This is its own `[[test]]` target, not
//! a case added to any of those files, exactly as each of their own
//! comments asks a later task's implementer to do.
//!
//! Every widget property here is read back the same way the other files'
//! are -- without pumping the main loop, since everything asserted (the
//! label's own text, the banner's own title and `revealed` state) is set
//! directly by `status_bar.rs`'s own code, not something a GTK layout pass
//! would need to compute first.
//!
//! `StatusBar::set_status`'s pure logic -- the three-way enforcing/not-
//! running/unknown word, the no-firewall and unreachable titles never
//! saying the same thing -- is unit-tested directly in `src/status_bar.rs`,
//! with no GTK involved. What this file adds is proof that the real
//! widgets carry that same text once actually built.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use porthole_core::ipc::WireStatus;
use porthole_gui::status_bar::StatusBar;

/// Identical in shape to the other test files' own `activate` helper: runs
/// `f` inside a real `adw::Application` activation, on the session bus
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

/// A `WireStatus` fixture. `backend_and_version` is `None` for "no firewall
/// at all" (`firewall_available: false`); `Some((name, version))` for an
/// installed backend, `active` deciding whether it is reported as
/// enforcing anything.
fn status(backend_and_version: Option<(&str, &str)>, active: bool) -> WireStatus {
    let (backend, version, available) = match backend_and_version {
        Some((backend, version)) => (backend.to_string(), version.to_string(), true),
        None => (String::new(), String::new(), false),
    };
    WireStatus {
        backend,
        firewall_available: available,
        firewall_active: active,
        firewall_active_unknown: false,
        firewall_version: version,
        location: String::new(),
        interface: String::new(),
        address: String::new(),
        cidr: String::new(),
        rules: Vec::new(),
    }
}

fn the_status_line_names_the_backend_and_whether_it_is_enforcing() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusEnforcing",
        move |_app| {
            let bar = StatusBar::new();
            bar.set_status(&status(Some(("firewalld", "2.4.4")), true));
            *seen.borrow_mut() = Some((bar.text(), bar.is_prominent()));
        },
    );
    let (text, prominent) = result.borrow_mut().take().ok_or("activation never ran")?;
    if !text.contains("firewalld") {
        return Err(format!("expected the backend's name in {text:?}"));
    }
    if !text.contains("2.4.4") {
        return Err(format!("expected the backend's version in {text:?}"));
    }
    if prominent {
        return Err("an installed, enforcing firewall must not be prominent".to_string());
    }
    Ok(())
}

/// With no firewall the port is already reachable. A grey line at the
/// bottom of the window is not where that belongs: the user would read the
/// rest of the app as if it were protecting them.
fn no_firewall_at_all_is_prominent_not_a_footnote() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusNoFirewall",
        move |_app| {
            let bar = StatusBar::new();
            bar.set_status(&status(None, false));
            *seen.borrow_mut() = Some((bar.text(), bar.is_prominent()));
        },
    );
    let (text, prominent) = result.borrow_mut().take().ok_or("activation never ran")?;
    if !prominent {
        return Err(
            "no firewall at all must not be rendered as an ordinary status line".to_string(),
        );
    }
    if !text.contains("already reachable") {
        return Err(format!("expected \"already reachable\" in {text:?}"));
    }
    Ok(())
}

fn an_installed_but_stopped_firewall_says_stopped_not_missing() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusStopped",
        move |_app| {
            let bar = StatusBar::new();
            bar.set_status(&status(Some(("firewalld", "2.4.4")), false));
            *seen.borrow_mut() = Some((bar.text(), bar.is_prominent()));
        },
    );
    let (text, prominent) = result.borrow_mut().take().ok_or("activation never ran")?;
    if !text.contains("not running") {
        return Err(format!("expected \"not running\" in {text:?}"));
    }
    if text.contains("no firewall") {
        return Err(format!(
            "an installed, stopped firewall must not read as \"no firewall\": {text:?}"
        ));
    }
    // The control half: an installed-but-stopped firewall is a fact worth
    // reading, but it is not the "everything is already reachable" case --
    // see `no_firewall_at_all_is_prominent_not_a_footnote` above for the
    // one that is.
    if prominent {
        return Err("an installed, stopped firewall must not be prominent".to_string());
    }
    Ok(())
}

/// The distinction this module exists to keep apart: "no firewall" is a
/// confirmed fact (this port genuinely is already reachable); "the helper
/// could not be reached" is an absence of information (porthole simply does
/// not know). Both are prominent -- neither is a footnote -- but only the
/// first may claim reachability.
fn an_unreachable_helper_is_prominent_but_does_not_claim_reachability() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusUnreachable",
        move |_app| {
            let bar = StatusBar::new();
            bar.set_unreachable("could not reach the porthole helper: timed out");
            *seen.borrow_mut() = Some((bar.text(), bar.is_prominent()));
        },
    );
    let (text, prominent) = result.borrow_mut().take().ok_or("activation never ran")?;
    if !prominent {
        return Err(
            "an unreachable helper must not be rendered as an ordinary status line".to_string(),
        );
    }
    if text.contains("already reachable") {
        return Err(format!(
            "an unreachable helper must not claim reachability either way: {text:?}"
        ));
    }
    if !text.to_lowercase().contains("helper") {
        return Err(format!("expected the text to name the helper: {text:?}"));
    }
    Ok(())
}

/// Three states, not two, mirroring `porthole-cli`'s own
/// `firewall_active_unknown` distinction: a firewall porthole could not
/// confirm the activity of must not read the same as one it confirmed is
/// stopped.
fn a_firewall_porthole_could_not_read_is_not_confused_with_a_confirmed_stop() -> Result<(), String>
{
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusUnknown",
        move |_app| {
            let bar = StatusBar::new();
            let mut unknown = status(Some(("ufw", "0.36.2")), false);
            unknown.firewall_active_unknown = true;
            bar.set_status(&unknown);
            *seen.borrow_mut() = Some(bar.text());
        },
    );
    let text = result.borrow_mut().take().ok_or("activation never ran")?;
    if text.contains("not running") {
        return Err(format!(
            "a firewall porthole could not read must not claim it confirmed a stop: {text:?}"
        ));
    }
    Ok(())
}

/// One named check, run by `main` below -- see `tests/window.rs`'s own
/// `Case` alias for why this is a type alias rather than spelled out
/// inline.
type Case = (&'static str, fn() -> Result<(), String>);

fn main() {
    let cases: [Case; 5] = [
        (
            "the_status_line_names_the_backend_and_whether_it_is_enforcing",
            the_status_line_names_the_backend_and_whether_it_is_enforcing,
        ),
        (
            "no_firewall_at_all_is_prominent_not_a_footnote",
            no_firewall_at_all_is_prominent_not_a_footnote,
        ),
        (
            "an_installed_but_stopped_firewall_says_stopped_not_missing",
            an_installed_but_stopped_firewall_says_stopped_not_missing,
        ),
        (
            "an_unreachable_helper_is_prominent_but_does_not_claim_reachability",
            an_unreachable_helper_is_prominent_but_does_not_claim_reachability,
        ),
        (
            "a_firewall_porthole_could_not_read_is_not_confused_with_a_confirmed_stop",
            a_firewall_porthole_could_not_read_is_not_confused_with_a_confirmed_stop,
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
