//! Runs the real update-consent dialog under Xvfb and writes a real
//! `update.toml`.
//!
//! `harness = false` (see `Cargo.toml`), and its own `[[test]]` target, for
//! the reason every other GTK-touching file here carries: gtk4-rs locks GTK
//! to whichever OS thread makes its first call, and cargo's normal harness
//! spawns a fresh thread per `#[test]`.
//!
//! One addition of its own, and the second reason this is not a case added to
//! `tests/window.rs`: this file points `PORTHOLE_UPDATE_FILE` at a temporary
//! directory, process-wide, before anything else runs. Every case below reads
//! -- and two of them write -- a real settings file through the real
//! `porthole_core::update::Settings`, and none of it may go anywhere near the
//! settings of whoever is running the tests. That variable is honoured in
//! debug builds only, which is what makes it safe to rely on here and what
//! makes a release binary unable to take a config path from its environment.
//!
//! # What these cases are about
//!
//! One thing, in four parts: that porthole asks **once**. A machine nobody
//! has asked gets the question; each of the two answers is written down and
//! ends the asking; and a **dismissal is not an answer**, so the question
//! survives it. That last one is the case that needs a test rather than a
//! reading: `AdwAlertDialog` emits `response` for a dismissal too, so a
//! dialog whose `close_response` named the "no" button would file a refusal
//! on behalf of somebody who pressed Escape -- and *no* is the answer that
//! stops porthole ever asking again.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;

use adw::prelude::*;

use porthole_core::update::{Consent, Settings};
use porthole_gui::update_consent::{self, HEADING, RESPONSE_NO, RESPONSE_YES};
use porthole_gui::window::PortholeWindow;

/// Identical in shape to every other GTK-touching file here: runs `f` inside
/// a real `adw::Application` activation, on the session bus
/// `dbus-run-session` provides.
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

fn pump_main_context() {
    let context = gtk::glib::MainContext::default();
    for _ in 0..50 {
        while context.iteration(false) {}
    }
}

/// The settings file every case here writes. One per process, named after
/// the process, and removed before each case so one case's answer is not
/// another's fixture.
fn settings_path() -> PathBuf {
    std::env::temp_dir()
        .join(format!("porthole-gui-update-{}", std::process::id()))
        .join("update.toml")
}

/// A machine nobody has asked anything on.
fn forget_the_answer() {
    let _ = std::fs::remove_file(settings_path());
}

/// What the file says now, read back through the same loader the application
/// uses.
fn recorded() -> Consent {
    Settings::load(&settings_path()).consent()
}

/// Builds a presented window with no initial load -- there is no system bus
/// in this container, and nothing here is about the helper.
fn window(app: &adw::Application) -> PortholeWindow {
    let win = PortholeWindow::new_without_initial_load(app);
    win.present();
    pump_main_context();
    win
}

fn a_machine_nobody_has_asked_is_asked() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    forget_the_answer();
    activate(
        "com.jacopobriccola.Porthole.Test.ConsentAsked",
        move |app| {
            let win = window(app);
            let dialog = update_consent::ask_if_never_asked(&*win);
            pump_main_context();
            seen.replace(Some((
                dialog.is_some(),
                dialog.map(|d| d.heading().map(|h| h.to_string())),
                win.visible_dialog().is_some(),
            )));
        },
    );
    let (asked, heading, on_screen) = result.borrow_mut().take().ok_or("activation never ran")?;
    if !asked {
        return Err("a machine nobody has asked must be asked".to_string());
    }
    if !on_screen {
        return Err("the question was built and never put on screen".to_string());
    }
    match heading.flatten() {
        Some(h) if h == HEADING => Ok(()),
        other => Err(format!(
            "the dialog's heading is {other:?}, not {HEADING:?}"
        )),
    }
}

/// Answers `response`, and reports what the file said afterwards and whether
/// the question would be put again.
fn answer_and_reread(app_id: &'static str, response: &'static str) -> (Consent, bool) {
    let result = Rc::new(Cell::new(None));
    let seen = result.clone();
    forget_the_answer();
    activate(app_id, move |app| {
        let win = window(app);
        let dialog =
            update_consent::ask_if_never_asked(&*win).expect("a machine nobody has asked is asked");
        pump_main_context();
        // The signal a button press emits, emitted on the real dialog.
        //
        // `emit_by_name` rather than a method: `adw::AlertDialog` has no
        // `response()` of its own in libadwaita 0.7 -- that method belongs to
        // `gtk::Dialog` and `adw::MessageDialog`, neither of which this is,
        // and reaching for it is a compile error (measured in this crate's
        // own container, which is the only place this crate compiles at all).
        // The `response` signal is what `ask_if_never_asked` connects to, so
        // emitting it is exactly what a press does.
        dialog.emit_by_name::<()>("response", &[&response]);
        pump_main_context();
        let again = update_consent::ask_if_never_asked(&*win).is_some();
        seen.set(Some((recorded(), again)));
    });
    result.get().expect("activation never ran")
}

fn answering_yes_is_recorded_and_the_question_is_not_put_again() -> Result<(), String> {
    let (consent, again) =
        answer_and_reread("com.jacopobriccola.Porthole.Test.ConsentYes", RESPONSE_YES);
    if consent != Consent::Yes {
        return Err(format!("pressing the yes button recorded {consent:?}"));
    }
    if again {
        return Err("somebody who said yes was asked again".to_string());
    }
    Ok(())
}

fn answering_no_is_recorded_and_the_question_is_not_put_again() -> Result<(), String> {
    // The half the three states exist for: a refusal has to be written down,
    // or it is indistinguishable from never having been asked and the
    // question comes back at every launch.
    let (consent, again) =
        answer_and_reread("com.jacopobriccola.Porthole.Test.ConsentNo", RESPONSE_NO);
    if consent != Consent::No {
        return Err(format!("pressing the no button recorded {consent:?}"));
    }
    if again {
        return Err("somebody who declined was asked again".to_string());
    }
    Ok(())
}

fn a_dismissal_is_not_an_answer_and_the_question_survives_it() -> Result<(), String> {
    // Escape, or clicking away. `AdwAlertDialog` emits `response` for this
    // too, carrying its `close_response` -- so a dialog that named the "no"
    // button there would file a refusal nobody gave, and *no* is the answer
    // that ends the asking for good.
    let result = Rc::new(Cell::new(None));
    let seen = result.clone();
    forget_the_answer();
    activate(
        "com.jacopobriccola.Porthole.Test.ConsentDismissed",
        move |app| {
            let win = window(app);
            let dialog = update_consent::ask_if_never_asked(&*win)
                .expect("a machine nobody has asked is asked");
            pump_main_context();
            dialog.close();
            pump_main_context();
            let again = update_consent::ask_if_never_asked(&*win).is_some();
            seen.set(Some((recorded(), again)));
        },
    );
    let (consent, again) = result.get().ok_or("activation never ran")?;
    if consent != Consent::NeverAsked {
        return Err(format!(
            "dismissing the dialog recorded {consent:?}; a dismissal is not an answer"
        ));
    }
    if !again {
        return Err(
            "the question did not survive a dismissal, so somebody who pressed Escape is \
             never asked again"
                .to_string(),
        );
    }
    Ok(())
}

type Case = (&'static str, fn() -> Result<(), String>);

fn main() {
    // Process-wide, before any case runs: every case below reads a real
    // settings file, and two of them write one. See this file's own module
    // doc for why that variable is safe to rely on here.
    std::env::set_var("PORTHOLE_UPDATE_FILE", settings_path());
    if let Some(parent) = settings_path().parent() {
        std::fs::create_dir_all(parent).expect("the temp directory is writable");
    }

    let cases: [Case; 4] = [
        (
            "a_machine_nobody_has_asked_is_asked",
            a_machine_nobody_has_asked_is_asked,
        ),
        (
            "answering_yes_is_recorded_and_the_question_is_not_put_again",
            answering_yes_is_recorded_and_the_question_is_not_put_again,
        ),
        (
            "answering_no_is_recorded_and_the_question_is_not_put_again",
            answering_no_is_recorded_and_the_question_is_not_put_again,
        ),
        (
            "a_dismissal_is_not_an_answer_and_the_question_survives_it",
            a_dismissal_is_not_an_answer_and_the_question_survives_it,
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

    forget_the_answer();
    if any_failed {
        std::process::exit(1);
    }
}
