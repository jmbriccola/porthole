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
use porthole_core::docker::Published;
use porthole_core::model::{Lifetime, Protocol, ScopeSpec, DEFAULT_DURATION, MAX_DURATION};
use porthole_gui::open_dialog::{DeviceEntry, OpenDialog, Request};
use porthole_gui::window::PortholeWindow;

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

/// The five fixed chips the spec names, in order, and then "Custom".
/// Nothing between 8 hours and until-reboot is offered as a fixed chip: a
/// chip offering 12 hours would be refused by the helper, an avoidable dead
/// end put on screen by the app itself. "Custom" offers no duration of its
/// own -- it reveals a field, and what that field accepts is
/// `porthole_core::validate::parse_duration`'s business.
fn the_duration_chips_are_the_five_fixed_ones_and_a_custom_field() -> Result<(), String> {
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
    let expected = vec![
        "15 minutes",
        "1 hour",
        "4 hours",
        "8 hours",
        "Until reboot",
        "Custom",
    ];
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
    let expected = Some(Lifetime::For(Duration::from_secs(3600)));
    if lifetime != expected {
        return Err(format!("expected {expected:?}, got {lifetime:?}"));
    }
    Ok(())
}

/// The dialog has to fit in the window porthole opens by default, and it
/// did not: the duration chips sat in one homogeneous "linked" row that
/// could neither wrap nor ellipsize, so the whole dialog's minimum width
/// was 606 px and libadwaita clipped it -- reported by the first person to
/// run the application, who hit it within two minutes.
///
/// Measured against the real `PortholeWindow`'s own default size rather
/// than against 480x560 written down here, so this cannot pass by agreeing
/// with a number the window has since stopped using. The content is the
/// widest and tallest this dialog can hold: a saved device whose name is
/// arbitrary user text, another carrying a resolver sentence, and the
/// custom-duration field showing the longest refusal
/// `porthole_core::validate::parse_duration` produces.
fn the_dialog_fits_the_window_porthole_opens_by_default() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate("com.jacopobriccola.Porthole.Test.DialogFits", move |app| {
        let win = PortholeWindow::new_without_initial_load(app);
        win.present();
        let dialog = OpenDialog::for_port(9000);
        dialog.set_current_network("10.10.10.0/24".parse().unwrap());
        dialog.set_devices(&[
            DeviceEntry {
                name: "living room television (the big one)".to_string(),
                resolved: Ok("10.10.10.31".parse().unwrap()),
            },
            DeviceEntry {
                name: "laptop".to_string(),
                resolved: Err(
                    "`laptop` (bc:24:11:5e:1c:6e) is not on this network right now".to_string(),
                ),
            },
        ]);
        let outcome = custom_chip(&dialog).map(|b| {
            b.emit_clicked();
            dialog.set_custom_duration_text("9h");
            dialog.present(Some(&*win));
            let content = dialog.dialog().child().expect("the dialog has a child");
            let (min_width, ..) = content.measure(gtk::Orientation::Horizontal, -1);
            let (min_height, ..) = content.measure(gtk::Orientation::Vertical, -1);
            (
                min_width,
                min_height,
                win.default_width(),
                win.default_height(),
            )
        });
        *seen.borrow_mut() = Some(outcome);
    });
    let (min_width, min_height, window_width, window_height) =
        result.borrow_mut().take().ok_or("activation never ran")??;
    if min_width > window_width {
        return Err(format!(
            "the dialog cannot narrow below {min_width} px, and the window opens {window_width} px wide"
        ));
    }
    if min_height > window_height {
        return Err(format!(
            "the dialog cannot shorten below {min_height} px, and the window opens {window_height} px tall"
        ));
    }
    Ok(())
}

/// The index of the "Custom" chip, found by its own displayed label rather
/// than written down as a number here -- the chip list is asserted
/// literally above, and this must not need editing when it changes.
fn custom_chip(dialog: &OpenDialog) -> Result<gtk::ToggleButton, String> {
    let index = dialog
        .duration_labels()
        .iter()
        .position(|l| l == "Custom")
        .ok_or("no chip is labelled Custom")?;
    dialog
        .duration_button(index)
        .ok_or_else(|| format!("no chip button at index {index}"))
}

/// The field is not on screen until the chip is actually pressed, and the
/// press is a real `emit_clicked` on the real button -- not `set_active`,
/// which would set the state a click sets and prove nothing about the click
/// reaching anything.
fn the_custom_field_appears_only_once_the_custom_chip_is_pressed() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.CustomReveal",
        move |_app| {
            let dialog = OpenDialog::for_port(5173);
            let before = dialog.custom_duration_is_revealed();
            let pressed = custom_chip(&dialog).map(|b| {
                b.emit_clicked();
                dialog.custom_duration_is_revealed()
            });
            *seen.borrow_mut() = Some((before, pressed));
        },
    );
    let (before, pressed) = result.borrow_mut().take().ok_or("activation never ran")?;
    if before {
        return Err("the custom field must start hidden".to_string());
    }
    if !pressed? {
        return Err("pressing the Custom chip must reveal the field".to_string());
    }
    Ok(())
}

/// The whole point of the field: a duration none of the fixed chips offers,
/// reaching the request the client would send.
fn a_typed_custom_duration_becomes_the_lifetime_that_would_be_sent() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.CustomAccepted",
        move |_app| {
            let dialog = OpenDialog::for_port(5173);
            let outcome = custom_chip(&dialog).map(|b| {
                b.emit_clicked();
                dialog.set_custom_duration_text("20m");
                (
                    dialog.request(),
                    dialog.open_button().is_sensitive(),
                    dialog.custom_duration_error(),
                )
            });
            *seen.borrow_mut() = Some(outcome);
        },
    );
    let (request, sensitive, error) =
        result.borrow_mut().take().ok_or("activation never ran")??;
    let expected = Some(Request {
        port: 5173,
        protocol: Protocol::Tcp,
        lifetime: Lifetime::For(Duration::from_secs(20 * 60)),
        scope: ScopeSpec::CurrentSubnet,
    });
    if request != expected {
        return Err(format!("expected {expected:?}, got {request:?}"));
    }
    if !sensitive {
        return Err("the Open button must be sensitive for a duration the tool takes".to_string());
    }
    if let Some(message) = error {
        return Err(format!(
            "a valid duration must show no error, got {message:?}"
        ));
    }
    Ok(())
}

/// Zero and anything over the ceiling: the refusal is said, and nothing is
/// submittable. Not clamped to the nearest allowed value -- a user who
/// asked for 9 hours and silently got 8 would not know.
///
/// The expected text is `porthole_core::validate::parse_duration`'s own,
/// computed here from that function rather than written out, so this
/// asserts the two are the same sentence rather than that this file's copy
/// of it has not changed.
fn a_refused_custom_duration_says_why_and_cannot_be_sent() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.CustomRefused",
        move |_app| {
            let dialog = OpenDialog::for_port(5173);
            let outcome = custom_chip(&dialog).map(|b| {
                b.emit_clicked();
                let mut seen = Vec::new();
                for text in ["0m", "9h", "20"] {
                    dialog.set_custom_duration_text(text);
                    seen.push((
                        text,
                        dialog.custom_duration_error(),
                        dialog.open_button().is_sensitive(),
                        dialog.request(),
                    ));
                }
                seen
            });
            *seen.borrow_mut() = Some(outcome);
        },
    );
    let cases = result.borrow_mut().take().ok_or("activation never ran")??;
    for (text, error, sensitive, request) in cases {
        let expected = porthole_core::validate::parse_duration(text)
            .err()
            .map(|e| e.to_string());
        if error != expected {
            return Err(format!(
                "for {text:?}: expected {expected:?}, got {error:?}"
            ));
        }
        if sensitive {
            return Err(format!("{text:?} must leave the Open button insensitive"));
        }
        if request.is_some() {
            return Err(format!("{text:?} must build no request, got {request:?}"));
        }
    }
    Ok(())
}

/// An empty field is not something to complain about, and is not a
/// duration either: no message, nothing submittable. And going back to a
/// fixed chip clears both, so a refused custom entry cannot leave the
/// dialog stuck.
fn an_empty_custom_field_says_nothing_and_a_fixed_chip_recovers() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.CustomEmpty",
        move |_app| {
            let dialog = OpenDialog::for_port(5173);
            let outcome = custom_chip(&dialog).and_then(|custom| {
                custom.emit_clicked();
                let empty = (
                    dialog.custom_duration_error(),
                    dialog.open_button().is_sensitive(),
                );
                dialog.set_custom_duration_text("9h");
                let refused = dialog.open_button().is_sensitive();
                let first = dialog
                    .duration_button(0)
                    .ok_or_else(|| "no chip at index 0".to_string())?;
                first.emit_clicked();
                Ok((
                    empty,
                    refused,
                    dialog.open_button().is_sensitive(),
                    dialog.custom_duration_error(),
                    dialog.custom_duration_is_revealed(),
                    dialog.selected_lifetime(),
                ))
            });
            *seen.borrow_mut() = Some(outcome);
        },
    );
    let ((empty_error, empty_sensitive), refused, recovered, error_after, revealed, lifetime) =
        result.borrow_mut().take().ok_or("activation never ran")??;
    if let Some(message) = empty_error {
        return Err(format!("an empty field must say nothing, got {message:?}"));
    }
    if empty_sensitive {
        return Err("an empty custom field must not be submittable".to_string());
    }
    if refused {
        return Err("9h must not be submittable".to_string());
    }
    if !recovered {
        return Err("going back to a fixed chip must make Open sensitive again".to_string());
    }
    if let Some(message) = error_after {
        return Err(format!(
            "the refusal must go with the field, got {message:?}"
        ));
    }
    if revealed {
        return Err("the field must be hidden again once a fixed chip is chosen".to_string());
    }
    if lifetime != Some(Lifetime::For(Duration::from_secs(15 * 60))) {
        return Err(format!("expected the 15-minute chip, got {lifetime:?}"));
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
            let scope = dialog
                .selected_scope()
                .expect("a target is always selected");
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
            let marked = dialog.is_marked_significant(labels.len() - 1);
            let scope = dialog
                .selected_scope()
                .expect("a target is always selected");
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

/// A saved device can be called anything, "Anyone" included, and then the
/// target list has two rows with one title. The marking belongs to the last
/// row and to no other -- which a lookup by title could not tell, since the
/// device sorts ahead of it.
fn a_device_named_anyone_does_not_take_the_real_anyones_marking() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DeviceNamedAnyone",
        move |_app| {
            let dialog = OpenDialog::new();
            dialog.set_devices(&[resolved("Anyone", "10.10.10.245")]);
            let labels = dialog.target_labels();
            *seen.borrow_mut() = Some((
                labels.clone(),
                // Index 1 is the device, index 2 the real "Anyone".
                dialog.is_marked_significant(1),
                dialog.is_marked_significant(labels.len() - 1),
            ));
        },
    );
    let (labels, device_marked, anyone_marked) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if labels != vec!["This network", "Anyone", "Anyone"] {
        return Err(format!("expected two rows titled Anyone, got {labels:?}"));
    }
    if device_marked {
        return Err("a device must not carry the significant-choice marking".to_string());
    }
    if !anyone_marked {
        return Err("the real \"Anyone\" must still carry it".to_string());
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
    // The same act-neutrality the unit guard holds, on the string the real
    // widget actually carries. This row appears on a forwarding dialog too,
    // where a sentence saying "opens the port" describes the accept
    // `firewalld.rs`'s own `forward` was measured into never writing.
    let lowered = note.to_lowercase();
    for act in ["open", "forward", "redirect"] {
        if lowered.contains(act) {
            return Err(format!(
                "the note is shared by both acts and must name neither (\"{act}\"): {note}"
            ));
        }
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

fn resolved(name: &str, addr: &str) -> DeviceEntry {
    DeviceEntry {
        name: name.to_string(),
        resolved: Ok(addr.parse().unwrap()),
    }
}

fn unresolved(name: &str, reason: &str) -> DeviceEntry {
    DeviceEntry {
        name: name.to_string(),
        resolved: Err(reason.to_string()),
    }
}

fn published_on_all(port: u16) -> Published {
    Published {
        host_addr: None,
        host_port: port,
        protocol: Protocol::Tcp,
        container_addr: "172.17.0.2".parse().unwrap(),
        container_port: 80,
    }
}

/// The spec's own order, on the real rows rather than on `build_targets`'s
/// return value (which `src/open_dialog.rs`'s own unit tests already pin).
fn saved_devices_are_rows_between_this_network_and_anyone() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate("com.jacopobriccola.Porthole.Test.DeviceRows", move |_app| {
        let dialog = OpenDialog::new();
        dialog.set_devices(&[
            resolved("phone", "10.10.10.245"),
            resolved("laptop", "10.10.10.17"),
        ]);
        *seen.borrow_mut() = Some(dialog.target_labels());
    });
    let labels = result.borrow_mut().take().ok_or("activation never ran")?;
    let expected = vec!["This network", "phone", "laptop", "Anyone"];
    if labels != expected {
        return Err(format!("expected {expected:?}, got {labels:?}"));
    }
    Ok(())
}

/// Shown, so it does not read as deleted; insensitive, so it cannot be
/// chosen; carrying the resolver's own sentence, so the user knows which of
/// the two it is.
fn an_unresolvable_device_is_shown_unselectable_with_its_reason() -> Result<(), String> {
    let reason = "`phone` (bc:24:11:5e:1c:6e) is not on this network right now";
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DeviceAbsent",
        move |_app| {
            let dialog = OpenDialog::new();
            dialog.set_devices(&[unresolved("phone", reason)]);
            // Index 1 by construction: "This network" is always 0, and the
            // one device follows it. `target_labels` is asserted below, so
            // a wrong index cannot pass quietly.
            *seen.borrow_mut() = Some((
                dialog.target_labels(),
                dialog.target_subtitles(),
                dialog.is_target_selectable(1),
                dialog.select_target(1),
                dialog.selected_scope(),
            ));
        },
    );
    let (labels, subtitles, selectable, selected, scope) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if !labels.contains(&"phone".to_string()) {
        return Err(format!("the row must still be listed, got {labels:?}"));
    }
    if !subtitles.contains(&reason.to_string()) {
        return Err(format!("the reason must be on the row, got {subtitles:?}"));
    }
    if selectable {
        return Err("an unresolvable device must not be selectable".to_string());
    }
    if selected {
        return Err("selecting an unresolvable device must not succeed".to_string());
    }
    if scope != Some(ScopeSpec::CurrentSubnet) {
        return Err(format!("the selection must not have moved, got {scope:?}"));
    }
    Ok(())
}

/// What choosing a device actually sends: that device's own address, as an
/// ordinary host scope -- never a device name, which the helper has never
/// heard of.
fn choosing_a_device_opens_towards_the_address_it_resolved_to() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DeviceScope",
        move |_app| {
            let dialog = OpenDialog::for_port(5173);
            dialog.set_devices(&[resolved("phone", "10.10.10.245")]);
            let chosen = dialog.select_target(1);
            *seen.borrow_mut() = Some((chosen, dialog.request()));
        },
    );
    let (chosen, request) = result.borrow_mut().take().ok_or("activation never ran")?;
    if !chosen {
        return Err("a resolved device must be selectable".to_string());
    }
    let expected = Some(Request {
        port: 5173,
        protocol: Protocol::Tcp,
        lifetime: Lifetime::For(DEFAULT_DURATION),
        scope: ScopeSpec::Host("10.10.10.245".parse().unwrap()),
    });
    if request != expected {
        return Err(format!("expected {expected:?}, got {request:?}"));
    }
    Ok(())
}

/// Devices reach the dialog from a cache a background read fills, so they
/// can land after the user has already chosen something. Inserting them
/// moves "Anyone" down the list; the choice must move with it.
fn a_device_list_arriving_later_does_not_move_the_users_choice() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DeviceLateArrival",
        move |_app| {
            let dialog = OpenDialog::new();
            // "Anyone" is index 1 while there are no devices, and index 3
            // once two arrive -- which is the whole point of this check.
            dialog.select_target(1);
            dialog.set_devices(&[
                resolved("phone", "10.10.10.245"),
                resolved("laptop", "10.10.10.17"),
            ]);
            *seen.borrow_mut() = Some(dialog.selected_scope());
        },
    );
    let scope = result.borrow_mut().take().ok_or("activation never ran")?;
    if scope != Some(ScopeSpec::Anywhere) {
        return Err(format!("expected Anywhere, got {scope:?}"));
    }
    Ok(())
}

/// The other half of the same property, and the one the first review found
/// untested: a device can leave the list too -- forgotten with `porthole
/// devices remove`, or simply gone by the next refresh -- and the row that
/// was selected then no longer exists. Nothing may inherit its position.
fn a_device_that_disappears_takes_the_selection_back_to_this_network() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DeviceRemoved",
        move |_app| {
            let dialog = OpenDialog::new();
            dialog.set_devices(&[
                resolved("phone", "10.10.10.245"),
                resolved("laptop", "10.10.10.17"),
            ]);
            // Index 2 is "laptop": This network, phone, laptop, Anyone.
            let chosen = dialog.select_target(2);
            let before = dialog.selected_scope();

            dialog.set_devices(&[resolved("phone", "10.10.10.245")]);
            let after = dialog.selected_scope();

            *seen.borrow_mut() = Some((chosen, before, after, dialog.target_labels()));
        },
    );
    let (chosen, before, after, labels) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if !chosen || before != Some(ScopeSpec::Host("10.10.10.17".parse().unwrap())) {
        return Err(format!(
            "the laptop must have been selected first: {before:?}"
        ));
    }
    if labels != vec!["This network", "phone", "Anyone"] {
        return Err(format!("the removed device must be gone: {labels:?}"));
    }
    // Not the phone, which now sits where the laptop sat, and not "Anyone",
    // which is the widest thing on the list.
    if after != Some(ScopeSpec::CurrentSubnet) {
        return Err(format!(
            "a removed device's selection must fall back to This network, got {after:?}"
        ));
    }
    Ok(())
}

/// "The address book could not be read" is not "there are no saved
/// devices", and the dialog says which one it is.
fn an_unreadable_address_book_is_not_an_empty_device_list() -> Result<(), String> {
    let reason = "could not read /home/u/.config/porthole/devices.toml: permission denied";
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DeviceBookUnreadable",
        move |_app| {
            let dialog = OpenDialog::new();
            dialog.set_devices_unreadable(reason);
            *seen.borrow_mut() = Some((dialog.target_labels(), dialog.target_group_description()));
        },
    );
    let (labels, description) = result.borrow_mut().take().ok_or("activation never ran")?;
    if labels != vec!["This network".to_string(), "Anyone".to_string()] {
        return Err(format!("no device rows should have been built: {labels:?}"));
    }
    if description.as_deref() != Some(reason) {
        return Err(format!(
            "expected the reason on screen, got {description:?}"
        ));
    }
    Ok(())
}

/// An explanation, not a prohibition: the alert exists, says what Docker
/// already did, and carries a real way through.
fn a_docker_managed_port_is_explained_with_a_way_through() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DockerAlert",
        move |_app| {
            let dialog = OpenDialog::for_port(8080);
            dialog.set_docker_ports(&[published_on_all(8080)]);
            let alert = dialog.docker_alert();
            *seen.borrow_mut() = Some(alert.map(|a| {
                (
                    a.body().to_string(),
                    a.has_response("open-anyway"),
                    a.has_response("cancel"),
                    a.close_response().to_string(),
                    a.default_response().map(|r| r.to_string()),
                )
            }));
        },
    );
    let alert = result
        .borrow_mut()
        .take()
        .ok_or("activation never ran")?
        .ok_or("a Docker-published port must produce an explanation")?;
    let (body, has_open, has_cancel, close, default) = alert;
    if !body.contains("Docker already publishes 8080/tcp") {
        return Err(format!("the body must be the advice itself, got: {body}"));
    }
    if !has_open || !has_cancel {
        return Err("the alert needs both a way through and a way out".to_string());
    }
    if close != "cancel" || default.as_deref() != Some("cancel") {
        return Err(format!(
            "dismissing the alert must not open: close={close}, default={default:?}"
        ));
    }
    Ok(())
}

/// Silence in the ordinary case is what makes the warning worth reading --
/// and "porthole could not check" is silence here too, exactly as
/// `porthole-cli`'s own `open` treats it.
fn no_alert_for_a_port_docker_has_no_rule_for_or_could_not_be_checked() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DockerNoAlert",
        move |_app| {
            let checked = OpenDialog::for_port(5173);
            checked.set_docker_ports(&[published_on_all(8080)]);

            let unchecked = OpenDialog::for_port(8080);
            unchecked.set_docker_unknown();

            *seen.borrow_mut() = Some((
                checked.docker_alert().is_some(),
                unchecked.docker_alert().is_some(),
            ));
        },
    );
    let (checked, unchecked) = result.borrow_mut().take().ok_or("activation never ran")?;
    if checked {
        return Err("a port Docker does not publish must produce no alert".to_string());
    }
    if unchecked {
        return Err("an unchecked Docker list must produce no alert".to_string());
    }
    Ok(())
}

/// Everything one dialog reports about itself, so the two acts can be
/// compared field by field rather than through a tuple nobody can read.
struct DialogFacts {
    forwards: Option<u16>,
    title: String,
    button_label: Option<String>,
    port: Option<u16>,
    port_field_title: String,
    port_explanation: Option<String>,
    offers_a_protocol_choice: bool,
    target_group_title: String,
    shows_a_docker_alert: bool,
}

fn facts_about(dialog: &OpenDialog) -> DialogFacts {
    DialogFacts {
        forwards: dialog.forwards(),
        title: dialog.dialog().title().to_string(),
        button_label: dialog.open_button().label().map(|l| l.to_string()),
        port: dialog.port(),
        port_field_title: dialog.port_field_title(),
        port_explanation: dialog.port_group_description(),
        offers_a_protocol_choice: dialog.offers_a_protocol_choice(),
        target_group_title: dialog.target_group_title(),
        shows_a_docker_alert: dialog.docker_alert().is_some(),
    }
}

/// The forwarding dialog is the same widgets making a different request,
/// and every part of that difference is on screen: what the port field is
/// called and what it means, that there is no protocol to choose, what the
/// target list is headed, and what the button says.
///
/// The title is checked too, but it is deliberately *not* the only thing
/// checked: this dialog carries no `adw::HeaderBar`, so its title is
/// metadata and a screen reader's announcement rather than text a person
/// reads. Every other field below is something visible in the rendered
/// image.
///
/// `forwards()` is the value the button's own handler reads to decide which
/// method to send, so a dialog that looked right and sent an `open` would
/// fail here too.
fn the_forward_dialog_says_it_redirects_and_sends_a_forward() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ForwardDialog",
        move |_app| {
            let forwarding = OpenDialog::for_forward(3000);
            // The Docker list a real window hands every dialog it presents.
            // On this one it must produce no explanation: that alert tells
            // someone opening a port that Docker publishes it, which is the
            // premise here, and its wording is about opening.
            forwarding.set_docker_ports(&[published_on_all(3000)]);

            let opening = OpenDialog::for_port(3000);
            opening.set_docker_ports(&[published_on_all(3000)]);

            *seen.borrow_mut() = Some((facts_about(&forwarding), facts_about(&opening)));
        },
    );
    let (forward, open) = result.borrow_mut().take().ok_or("activation never ran")?;

    if forward.forwards != Some(3000) {
        return Err(format!(
            "the forwarding dialog must send a forward for the published port, got {:?}",
            forward.forwards
        ));
    }
    if open.forwards.is_some() {
        return Err("an ordinary open dialog must not send a forward".to_string());
    }
    if !forward.title.to_lowercase().contains("forward") {
        return Err(format!(
            "a dialog that redirects must not be titled like one that permits: {:?}",
            forward.title
        ));
    }
    if forward.title == open.title {
        return Err(format!(
            "the two dialogs must not share a title: both {:?}",
            forward.title
        ));
    }
    match forward.button_label.as_deref() {
        Some(label) if label.to_lowercase().contains("forward") => {}
        other => {
            return Err(format!(
                "the button must say which act it performs, got {other:?}"
            ))
        }
    }
    if forward.port != Some(3000) {
        return Err(format!(
            "omitting `--as` forwards to the same number, so the field starts there: {:?}",
            forward.port
        ));
    }

    // The visible half. A person never sees either dialog's title, so if
    // these were to converge the two would be indistinguishable on screen
    // while every check above still passed.
    if forward.port_field_title == open.port_field_title {
        return Err(format!(
            "the field takes a different number in the two acts and must not share a name: \
             both {:?}",
            forward.port_field_title
        ));
    }
    if !forward.port_field_title.to_lowercase().contains("network") {
        return Err(format!(
            "the forwarding field takes the port the *network* connects to: {:?}",
            forward.port_field_title
        ));
    }
    match forward.port_explanation.as_deref() {
        Some(text) if text.contains("3000") && text.to_lowercase().contains("container") => {}
        other => {
            return Err(format!(
                "the field must say where what arrives on it goes, and name the published \
                 port it goes to: {other:?}"
            ))
        }
    }
    if open.port_explanation.is_some() {
        return Err(format!(
            "an ordinary open's port field needs no explaining: {:?}",
            open.port_explanation
        ));
    }
    if forward.offers_a_protocol_choice {
        return Err(
            "the helper forwards TCP only, so the protocol chooser must be hidden rather \
             than offered and refused"
                .to_string(),
        );
    }
    if !open.offers_a_protocol_choice {
        return Err("fixture setup: an ordinary open still chooses a protocol".to_string());
    }
    if !forward
        .target_group_title
        .to_lowercase()
        .contains("forward")
    {
        return Err(format!(
            "the target list heads the act it is choosing for: {:?}",
            forward.target_group_title
        ));
    }
    if forward.target_group_title == open.target_group_title {
        return Err(format!(
            "the two target lists must not share a heading: both {:?}",
            forward.target_group_title
        ));
    }

    if forward.shows_a_docker_alert {
        return Err(
            "the Docker explanation must not be shown on a dialog whose whole premise is a \
             Docker-published port"
                .to_string(),
        );
    }
    if !open.shows_a_docker_alert {
        return Err(
            "fixture setup: the same list must still explain itself on an ordinary open"
                .to_string(),
        );
    }
    Ok(())
}

/// One named check, run by `main` below -- see `tests/window.rs`'s own
/// `Case` alias for why this is a type alias rather than spelled out
/// inline.
type Case = (&'static str, fn() -> Result<(), String>);

fn main() {
    let cases: [Case; 25] = [
        (
            "the_duration_chips_are_the_five_fixed_ones_and_a_custom_field",
            the_duration_chips_are_the_five_fixed_ones_and_a_custom_field,
        ),
        (
            "the_dialog_fits_the_window_porthole_opens_by_default",
            the_dialog_fits_the_window_porthole_opens_by_default,
        ),
        (
            "the_custom_field_appears_only_once_the_custom_chip_is_pressed",
            the_custom_field_appears_only_once_the_custom_chip_is_pressed,
        ),
        (
            "a_typed_custom_duration_becomes_the_lifetime_that_would_be_sent",
            a_typed_custom_duration_becomes_the_lifetime_that_would_be_sent,
        ),
        (
            "a_refused_custom_duration_says_why_and_cannot_be_sent",
            a_refused_custom_duration_says_why_and_cannot_be_sent,
        ),
        (
            "an_empty_custom_field_says_nothing_and_a_fixed_chip_recovers",
            an_empty_custom_field_says_nothing_and_a_fixed_chip_recovers,
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
            "a_device_named_anyone_does_not_take_the_real_anyones_marking",
            a_device_named_anyone_does_not_take_the_real_anyones_marking,
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
        (
            "saved_devices_are_rows_between_this_network_and_anyone",
            saved_devices_are_rows_between_this_network_and_anyone,
        ),
        (
            "an_unresolvable_device_is_shown_unselectable_with_its_reason",
            an_unresolvable_device_is_shown_unselectable_with_its_reason,
        ),
        (
            "choosing_a_device_opens_towards_the_address_it_resolved_to",
            choosing_a_device_opens_towards_the_address_it_resolved_to,
        ),
        (
            "a_device_list_arriving_later_does_not_move_the_users_choice",
            a_device_list_arriving_later_does_not_move_the_users_choice,
        ),
        (
            "a_device_that_disappears_takes_the_selection_back_to_this_network",
            a_device_that_disappears_takes_the_selection_back_to_this_network,
        ),
        (
            "an_unreadable_address_book_is_not_an_empty_device_list",
            an_unreadable_address_book_is_not_an_empty_device_list,
        ),
        (
            "a_docker_managed_port_is_explained_with_a_way_through",
            a_docker_managed_port_is_explained_with_a_way_through,
        ),
        (
            "no_alert_for_a_port_docker_has_no_rule_for_or_could_not_be_checked",
            no_alert_for_a_port_docker_has_no_rule_for_or_could_not_be_checked,
        ),
        (
            "the_forward_dialog_says_it_redirects_and_sends_a_forward",
            the_forward_dialog_says_it_redirects_and_sends_a_forward,
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
