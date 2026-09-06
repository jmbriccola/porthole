//! Runs a real `OpenDialog` inside an activated `adw::Application`, the same
//! way `tests/window.rs`, `tests/open_now.rs` and `tests/listening.rs` do
//! and for the identical reason: `harness = false` (see `Cargo.toml`)
//! because cargo's normal test harness spawns each `#[test]` function on its
//! own OS thread, and gtk4-rs locks GTK to whichever thread makes its first
//! call -- a second GTK-touching test thread wedges the whole process. This
//! is its own `[[test]]` target, not a case added to any of those files,
//! exactly as each of their own comments asks a later task's implementer to
//! do.
//!
//! Every widget property here is read back the same way `tests/open_now.rs`
//! and `tests/listening.rs`'s are -- without pumping the main loop, since
//! everything asserted (button labels, active state, row titles, sensitivity)
//! is set directly by `open_dialog.rs`'s own code, not something a GTK
//! layout pass would need to compute first.
//!
//! The pure logic behind these renders -- the five duration options, the
//! target-list data, the wire vocabulary, the note's own wording -- is
//! unit-tested directly in `src/open_dialog.rs`, with no GTK involved. What
//! this file adds is proof that the real widgets carry that same data once
//! actually built, and that a real click on the port entry actually flips
//! the real "Open" button's sensitivity.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;
use porthole_core::model::{Lifetime, Protocol, ScopeSpec, DEFAULT_DURATION, MAX_DURATION};
use porthole_gui::open_dialog::{OpenDialog, Request};

/// Identical in shape to `tests/window.rs`, `tests/open_now.rs` and
/// `tests/listening.rs`'s own `activate` helper: runs `f` inside a real
/// `adw::Application` activation, on the session bus `dbus-run-session`
/// provides (see `tests/container/gui-test.sh`).
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

/// Not four, not six, and nothing between 8 hours and until-reboot. The
/// ceiling is what makes porthole's promise true, and a chip offering 12
/// hours would be refused by the helper -- an avoidable dead end put on
/// screen by the app itself.
fn the_duration_chips_are_exactly_the_five_the_spec_names() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DurationChips",
        move |_app| {
            let dialog = OpenDialog::new();
            *seen.borrow_mut() = Some(dialog.duration_labels());
        },
    );
    let labels = result.borrow_mut().take().ok_or("activation never ran")?;
    let expected = vec!["15 minutes", "1 hour", "4 hours", "8 hours", "Until reboot"];
    if labels != expected {
        return Err(format!("expected {expected:?}, got {labels:?}"));
    }
    Ok(())
}

fn one_hour_is_selected_when_the_dialog_opens() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DefaultLifetime",
        move |_app| {
            let dialog = OpenDialog::new();
            *seen.borrow_mut() = Some(dialog.selected_lifetime());
        },
    );
    let lifetime = result.borrow_mut().take().ok_or("activation never ran")?;
    let expected = Lifetime::For(Duration::from_secs(3600));
    if lifetime != expected {
        return Err(format!("expected {expected:?}, got {lifetime:?}"));
    }
    Ok(())
}

/// Belt and braces: the chip list is asserted literally above, and this
/// asserts the property behind it, so adding a chip cannot quietly
/// introduce one the helper will refuse.
fn no_chip_can_ask_for_more_than_the_ceiling() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.CeilingChips",
        move |_app| {
            let dialog = OpenDialog::new();
            *seen.borrow_mut() = Some(dialog.all_lifetimes());
        },
    );
    let lifetimes = result.borrow_mut().take().ok_or("activation never ran")?;
    for lifetime in lifetimes {
        if let Lifetime::For(d) = lifetime {
            if d > MAX_DURATION {
                return Err(format!("{d:?} exceeds the ceiling"));
            }
        }
    }
    Ok(())
}

/// "This network" alone is not enough: the user has to be able to check it
/// is the network they think they are on.
fn this_network_is_the_default_target_and_names_the_actual_subnet() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.TargetSubnet",
        move |_app| {
            let dialog = OpenDialog::new();
            dialog.set_current_network("192.168.177.0/24".parse().unwrap());
            let label = dialog.target_labels()[0].clone();
            let scope = dialog.selected_scope();
            *seen.borrow_mut() = Some((label, scope));
        },
    );
    let (label, scope) = result.borrow_mut().take().ok_or("activation never ran")?;
    if label != "This network (192.168.177.0/24)" {
        return Err(format!(
            "expected \"This network (192.168.177.0/24)\", got {label:?}"
        ));
    }
    if scope != ScopeSpec::CurrentSubnet {
        return Err(format!("expected CurrentSubnet, got {scope:?}"));
    }
    Ok(())
}

fn anyone_is_last_marked_and_never_preselected() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.AnyoneMarked",
        move |_app| {
            let dialog = OpenDialog::new();
            let labels = dialog.target_labels();
            let last_is_anyone = labels.last().map(|s| s.as_str()) == Some("Anyone");
            let marked = dialog.is_marked_significant("Anyone");
            let scope = dialog.selected_scope();
            *seen.borrow_mut() = Some((last_is_anyone, marked, scope));
        },
    );
    let (last_is_anyone, marked, scope) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if !last_is_anyone {
        return Err("\"Anyone\" must be the last target".to_string());
    }
    if !marked {
        return Err("\"Anyone\" must carry the significant-choice marking".to_string());
    }
    if scope == ScopeSpec::Anywhere {
        return Err("\"Anyone\" must not be preselected".to_string());
    }
    Ok(())
}

/// The spec: "niente toni allarmistici o didattici, solo una frase asciutta
/// su cosa comporta". A warning that lectures gets dismissed unread, which
/// makes the genuinely significant choice less safe, not more.
fn the_note_on_anyone_is_one_dry_sentence_with_no_scolding() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate("com.jacopobriccola.Porthole.Test.AnyoneNote", move |_app| {
        let dialog = OpenDialog::new();
        *seen.borrow_mut() = Some(dialog.note_for_anyone());
    });
    let note = result.borrow_mut().take().ok_or("activation never ran")?;
    if note.matches('.').count() != 1 {
        return Err(format!("expected one sentence, got: {note}"));
    }
    for scolding in ["careful", "dangerous", "warning", "risk", "are you sure"] {
        if note.to_lowercase().contains(scolding) {
            return Err(format!("note scolds (\"{scolding}\"): {note}"));
        }
    }
    if !note.contains("anyone your machine can reach") {
        return Err(format!("note must say what it means: {note}"));
    }
    Ok(())
}

fn a_dialog_built_for_a_port_pre_fills_that_port() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.PreFilledPort",
        move |_app| {
            let dialog = OpenDialog::for_port(5173);
            *seen.borrow_mut() = Some(dialog.port());
        },
    );
    let port = result.borrow_mut().take().ok_or("activation never ran")?;
    if port != Some(5173) {
        return Err(format!("expected Some(5173), got {port:?}"));
    }
    Ok(())
}

fn port_zero_is_rejected_before_anything_is_sent() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate("com.jacopobriccola.Porthole.Test.PortZero", move |_app| {
        let dialog = OpenDialog::new();
        dialog.set_port_text("0");
        *seen.borrow_mut() = Some(dialog.can_submit());
    });
    let can_submit = result.borrow_mut().take().ok_or("activation never ran")?;
    if can_submit {
        return Err("port 0 must not be submittable".to_string());
    }
    Ok(())
}

/// The real "Open" button's own sensitivity, not just the semantic
/// `can_submit()` accessor -- proof the port entry's `changed` signal is
/// actually wired to it, not merely that the two happen to agree by
/// construction.
fn the_open_button_tracks_whether_the_port_is_valid() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.SubmitSensitivity",
        move |_app| {
            let dialog = OpenDialog::new();
            let before_any_port = dialog.open_button().is_sensitive();
            dialog.set_port_text("5173");
            let after_valid_port = dialog.open_button().is_sensitive();
            dialog.set_port_text("0");
            let after_invalid_port = dialog.open_button().is_sensitive();
            *seen.borrow_mut() = Some((before_any_port, after_valid_port, after_invalid_port));
        },
    );
    let (before, after_valid, after_invalid) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if before {
        return Err("the Open button must start insensitive with no port typed".to_string());
    }
    if !after_valid {
        return Err("the Open button must become sensitive once a real port is typed".to_string());
    }
    if after_invalid {
        return Err("the Open button must go back to insensitive for port 0".to_string());
    }
    Ok(())
}

/// What pressing Open actually builds and would hand to the client -- port,
/// protocol, lifetime and scope, never a rule. TCP and "1 hour" are what a
/// dialog with nothing changed defaults to; `CurrentSubnet` is what a fresh
/// dialog (no `set_current_network` call) still selects by default.
fn a_ready_dialog_produces_the_request_the_client_would_send() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate("com.jacopobriccola.Porthole.Test.Request", move |_app| {
        let dialog = OpenDialog::for_port(5173);
        *seen.borrow_mut() = Some(dialog.request());
    });
    let request = result.borrow_mut().take().ok_or("activation never ran")?;
    let expected = Some(Request {
        port: 5173,
        protocol: Protocol::Tcp,
        lifetime: Lifetime::For(DEFAULT_DURATION),
        scope: ScopeSpec::CurrentSubnet,
    });
    if request != expected {
        return Err(format!("expected {expected:?}, got {request:?}"));
    }
    Ok(())
}

/// One named check, run by `main` below -- see `tests/window.rs`'s own
/// `Case` alias for why this is a type alias rather than spelled out
/// inline.
type Case = (&'static str, fn() -> Result<(), String>);

fn main() {
    let cases: [Case; 10] = [
        (
            "the_duration_chips_are_exactly_the_five_the_spec_names",
            the_duration_chips_are_exactly_the_five_the_spec_names,
        ),
        (
            "one_hour_is_selected_when_the_dialog_opens",
            one_hour_is_selected_when_the_dialog_opens,
        ),
        (
            "no_chip_can_ask_for_more_than_the_ceiling",
            no_chip_can_ask_for_more_than_the_ceiling,
        ),
        (
            "this_network_is_the_default_target_and_names_the_actual_subnet",
            this_network_is_the_default_target_and_names_the_actual_subnet,
        ),
        (
            "anyone_is_last_marked_and_never_preselected",
            anyone_is_last_marked_and_never_preselected,
        ),
        (
            "the_note_on_anyone_is_one_dry_sentence_with_no_scolding",
            the_note_on_anyone_is_one_dry_sentence_with_no_scolding,
        ),
        (
            "a_dialog_built_for_a_port_pre_fills_that_port",
            a_dialog_built_for_a_port_pre_fills_that_port,
        ),
        (
            "port_zero_is_rejected_before_anything_is_sent",
            port_zero_is_rejected_before_anything_is_sent,
        ),
        (
            "the_open_button_tracks_whether_the_port_is_valid",
            the_open_button_tracks_whether_the_port_is_valid,
        ),
        (
            "a_ready_dialog_produces_the_request_the_client_would_send",
            a_ready_dialog_produces_the_request_the_client_would_send,
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
