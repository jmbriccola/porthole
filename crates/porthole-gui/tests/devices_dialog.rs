//! Runs a real `DevicesDialog` under Xvfb and writes a real address book.
//!
//! `harness = false` (see `Cargo.toml`), and its own `[[test]]` target, for
//! the reason every other GTK-touching file here carries: gtk4-rs locks GTK
//! to whichever OS thread makes its first call, and cargo's normal harness
//! spawns a fresh thread per `#[test]`.
//!
//! One addition of its own, and the second reason this is not a case added
//! to `tests/open_dialog.rs`: this file points `PORTHOLE_DEVICES_FILE` at a
//! temporary directory, process-wide, before anything else runs. Every save
//! and every forget below writes a real `devices.toml` through the real
//! `porthole_core::devices::Book`, and none of it may go anywhere near the
//! address book of whoever is running the tests. That variable is honoured
//! in debug builds only, which is what makes this safe to rely on and what
//! makes a release binary unable to take a config path from the
//! environment.
//!
//! The chain these cases exist to hold down runs end to end without a
//! helper, because the address book has nothing to do with the helper: the
//! Save button writes `devices.toml`, `window::load_devices` reads it back
//! and resolves it, and an `OpenDialog` fed that snapshot offers the device
//! as a target. Before `DevicesDialog` existed there was no first step --
//! the book could only be written from a terminal.
//!
//! **`ip` is not installed in this container.** So
//! `porthole_core::devices::resolve` does not fail here with "the device is
//! not on this network"; it fails with the command it could not run, which
//! is a different fact and renders as itself. The cases below never assume
//! which of the two they will get: where the text matters they compute the
//! expected one by calling `resolve` themselves.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use adw::prelude::*;

use porthole_core::command::RealRunner;
use porthole_core::devices;
use porthole_gui::devices_dialog::{DevicesDialog, NeighbourChoice, SavedDevice};
use porthole_gui::open_dialog::OpenDialog;
use porthole_gui::window::{self, PortholeWindow};

/// Identical in shape to every other GTK-touching file here: runs `f`
/// inside a real `adw::Application` activation, on the session bus
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

/// Drains the main context until `condition` holds or `timeout` runs out.
/// A save here crosses GLib's I/O thread pool, so its result lands on a
/// later iteration than the click that started it.
fn pump_until(condition: impl Fn() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        pump_main_context();
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    condition()
}

/// The address book every case here writes. One per process, named after
/// the process, and emptied before each case so one case's devices are not
/// another's fixture.
fn book_path() -> PathBuf {
    std::env::temp_dir()
        .join(format!("porthole-gui-devices-{}", std::process::id()))
        .join("devices.toml")
}

fn reset_book() {
    let path = book_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("the temporary book directory");
    }
    let _ = std::fs::remove_file(&path);
}

fn saved_names() -> Vec<String> {
    devices::Book::load(&book_path())
        .expect("the book loads")
        .devices()
        .iter()
        .map(|d| d.name.clone())
        .collect()
}

fn choice(mac: &str, address: &str) -> NeighbourChoice {
    named_choice(mac, address, None)
}

fn named_choice(mac: &str, address: &str, name: Option<&str>) -> NeighbourChoice {
    NeighbourChoice {
        mac: mac.to_string(),
        address: address.parse().unwrap(),
        interface: "wlo1".to_string(),
        name: name.map(str::to_string),
    }
}

// ---------------------------------------------------------------------
// The ways out of this panel. Two, not the open dialog's three: there is
// no Cancel here, and `devices_dialog.rs`'s own construction comment says
// why -- this is a management panel whose button saves one device and
// leaves the panel open for the next, so "Cancel" beside it would name
// backing out of a save rather than closing anything.
// ---------------------------------------------------------------------

/// Drains the main context *and lets real time pass between rounds*.
///
/// The plain `pump_main_context` above is enough for everything else in
/// this file, and not for these two: presenting an `adw::Dialog` and
/// dismissing one both run on the frame clock, which non-blocking
/// iterations never advance. Same helper, same reason, as
/// `tests/open_dialog.rs`'s own -- duplicated because each `harness = false`
/// target is its own binary.
fn settle() {
    for _ in 0..10 {
        pump_main_context();
        std::thread::sleep(Duration::from_millis(50));
    }
    pump_main_context();
}

/// The panel's own close button, found by the `close` style class GTK puts
/// on the one an `adw::HeaderBar` draws. `None` when there is no header bar,
/// which is the state this milestone repaired.
fn close_button_of(dialog: &adw::Dialog) -> Option<gtk::Button> {
    fn walk(widget: &gtk::Widget, found: &mut Vec<gtk::Button>) {
        if let Some(button) = widget.downcast_ref::<gtk::Button>() {
            if button.has_css_class("close") {
                found.push(button.clone());
            }
        }
        let mut child = widget.first_child();
        while let Some(w) = child {
            walk(&w, found);
            child = w.next_sibling();
        }
    }
    let mut found = Vec::new();
    walk(dialog.clone().upcast_ref::<gtk::Widget>(), &mut found);
    found.into_iter().next()
}

/// Until this milestone the saved-devices panel had no visible way to close
/// it either, for the identical reason the open dialog did not: no header
/// bar, so no close button.
///
/// The press is real and what is asserted is that the panel is gone, not
/// that a button exists.
fn the_close_button_dismisses_the_saved_devices_panel() -> Result<(), String> {
    let outcome = Rc::new(RefCell::new(Err("activation never ran".to_string())));
    let seen = outcome.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DevicesCloseButton",
        move |app| {
            let win = PortholeWindow::new_without_initial_load(app);
            win.present();
            let dialog = DevicesDialog::new();
            dialog.present(Some(&*win));
            settle();

            let mut result: Result<(), String> = Ok(());
            if win.visible_dialog().is_none() {
                result = Err("fixture setup: the panel was never on screen".to_string());
            }
            if result.is_ok() {
                match close_button_of(dialog.dialog()) {
                    Some(button) => {
                        button.emit_clicked();
                        settle();
                        if win.visible_dialog().is_some() {
                            result =
                                Err("pressing the close button left the panel on screen"
                                    .to_string());
                        }
                    }
                    None => {
                        result = Err(
                            "the panel carries no close button -- an adw::Dialog draws one \
                             only where an adw::HeaderBar asks for it"
                                .to_string(),
                        )
                    }
                }
            }
            *seen.borrow_mut() = result;
        },
    );
    outcome.replace(Err("activation never ran".to_string()))
}

/// Whether `widget` is `ancestor` or sits under it.
fn is_inside(widget: &gtk::Widget, ancestor: &gtk::Widget) -> bool {
    let mut current = Some(widget.clone());
    while let Some(w) = current {
        if w == *ancestor {
            return true;
        }
        current = w.parent();
    }
    false
}

/// Runs GTK's own bubble phase for an Escape key press delivered to
/// `focus`: every widget from there up to the window, firing any Escape
/// shortcut it carries and stopping at the first that reports it handled the
/// key.
///
/// The same helper, the same mechanism and the same one gap as
/// `tests/open_dialog.rs`'s own -- GDK4 exposes no way to construct a key
/// event and this container has no XTEST client, so the step not covered is
/// GDK turning a physical keypress into the event. Duplicated rather than
/// shared because each `harness = false` target is its own binary.
fn escape_from(focus: &gtk::Widget) -> Vec<String> {
    use gtk::prelude::ListModelExtManual;
    let mut fired = Vec::new();
    let mut current = Some(focus.clone());
    while let Some(widget) = current {
        for controller in widget
            .observe_controllers()
            .iter::<gtk::glib::Object>()
            .flatten()
        {
            let Ok(shortcuts) = controller.downcast::<gtk::ShortcutController>() else {
                continue;
            };
            for item in shortcuts.iter::<gtk::glib::Object>().flatten() {
                let Ok(shortcut) = item.downcast::<gtk::Shortcut>() else {
                    continue;
                };
                if shortcut
                    .trigger()
                    .map(|t| t.to_str().to_string())
                    .as_deref()
                    != Some("Escape")
                {
                    continue;
                }
                let Some(action) = shortcut.action() else {
                    continue;
                };
                let handled = action.activate(gtk::ShortcutActionFlags::empty(), &widget, None);
                fired.push(format!("{}:{handled}", widget.type_().name()));
                if handled {
                    return fired;
                }
            }
        }
        current = widget.parent();
    }
    fired
}

/// The panel's second way out, which the open dialog pins and this one did
/// not: its module doc names Escape as one of two, and only the close button
/// was ever pressed.
///
/// Two things, in order. The keyboard is inside the panel -- libadwaita's
/// Escape shortcut hangs off the sheet a presented dialog sits in and only
/// fires for an event that reaches it, so a keyboard left outside is a panel
/// Escape does nothing to. Then firing that chain actually dismisses.
fn escape_dismisses_the_saved_devices_panel() -> Result<(), String> {
    let outcome = Rc::new(RefCell::new(Err("activation never ran".to_string())));
    let seen = outcome.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DevicesEscape",
        move |app| {
            let win = PortholeWindow::new_without_initial_load(app);
            win.present();
            let dialog = DevicesDialog::new();
            dialog.present(Some(&*win));
            settle();

            let panel: gtk::Widget = dialog.dialog().clone().upcast();
            let focus = gtk::prelude::GtkWindowExt::focus(&*win);
            let inside = focus.as_ref().map(|f| is_inside(f, &panel));
            let where_it_is = focus
                .as_ref()
                .map(|f| f.type_().name().to_string())
                .unwrap_or_else(|| "nothing at all".to_string());

            *seen.borrow_mut() = if inside != Some(true) {
                Err(format!(
                    "a freshly presented panel must hold the keyboard, or Escape reaches \
                     nothing until the user clicks into it: the focus is on {where_it_is}"
                ))
            } else {
                let fired = focus.as_ref().map(escape_from).unwrap_or_default();
                settle();
                if win.visible_dialog().is_some() {
                    Err(format!(
                        "Escape left the panel on screen; the shortcuts it reached were \
                         {fired:?}"
                    ))
                } else {
                    Ok(())
                }
            };
        },
    );
    outcome.replace(Err("activation never ran".to_string()))
}

/// The keyboard lands on the name field, not on the header bar.
///
/// A control of the case above rather than a repeat of it, and the reason
/// this file needs both. "Inside the panel" is what Escape needs, and it is
/// satisfied just as well by the header bar's own close button, so it says
/// nothing about where typing goes. The panel's first act is typing a name;
/// this is what pins the keyboard there.
///
/// **What it does not do**, stated because the obvious reading is wrong:
/// it does not fail when `dialog.set_focus(Some(&name_row))` is deleted
/// from `devices_dialog.rs`. Measured, with the crate confirmed rebuilt --
/// on this panel that call is inert, because the only thing its header bar
/// puts ahead of the form is the close button and GTK's tab order skips it.
/// Nothing can detect the removal of a line that changes no behaviour. What
/// this check does catch is the behaviour itself moving, from whatever
/// cause: the same deletion on the *open* dialog, whose bar does carry a
/// focusable Cancel, moves the keyboard onto it and fails that panel's own
/// `the_keyboard_starts_in_the_port_field`.
fn the_keyboard_starts_in_the_name_field() -> Result<(), String> {
    let outcome = Rc::new(RefCell::new(Err("activation never ran".to_string())));
    let seen = outcome.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DevicesInitialFocus",
        move |app| {
            let win = PortholeWindow::new_without_initial_load(app);
            win.present();
            let dialog = DevicesDialog::new();
            dialog.present(Some(&*win));
            settle();

            let focus = gtk::prelude::GtkWindowExt::focus(&*win);
            // The row itself is what `devices_dialog.rs` names; what takes
            // the keyboard is the `GtkText` libadwaita builds inside it, so
            // the question is whether the focus sits under the row.
            let row: gtk::Widget = dialog.name_row().clone().upcast();
            let inside = focus.as_ref().map(|f| is_inside(f, &row));
            let where_it_is = focus
                .map(|f| f.type_().name().to_string())
                .unwrap_or_else(|| "nothing at all".to_string());

            *seen.borrow_mut() = if inside == Some(true) {
                Ok(())
            } else {
                Err(format!(
                    "a freshly opened panel must be ready to have a name typed into it, and \
                     the keyboard is on {where_it_is}"
                ))
            };
        },
    );
    outcome.replace(Err("activation never ran".to_string()))
}

/// A picker row carries whatever the resolver answered for its address, and
/// a row it answered nothing for carries no substitute for one.
///
/// The MAC stays the row's title in both cases. That is what the row writes
/// into the field and what the book records, and this asserts it against
/// the real widgets rather than against the values handed in.
fn a_row_shows_a_name_where_there_is_one_and_invents_none_where_there_is_not() -> Result<(), String>
{
    reset_book();
    let outcome: Rc<RefCell<Result<(), String>>> =
        Rc::new(RefCell::new(Err("activation never ran".to_string())));
    let seen = outcome.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DeviceNames",
        move |_app| {
            let dialog = DevicesDialog::new();
            dialog.set_neighbours(&[
                named_choice("bc:24:11:5e:1c:6e", "10.10.10.245", Some("phone.example")),
                named_choice("de:ad:be:ef:00:01", "10.10.10.7", None),
            ]);

            let titles = dialog.neighbour_labels();
            let subtitles = dialog.neighbour_subtitles();
            *seen.borrow_mut() = (|| {
                if titles != vec!["bc:24:11:5e:1c:6e", "de:ad:be:ef:00:01"] {
                    return Err(format!("the MAC stays the row's title, got {titles:?}"));
                }
                if subtitles[0] != "phone.example · 10.10.10.245 on wlo1" {
                    return Err(format!(
                        "a row with a name shows it, got `{}`",
                        subtitles[0]
                    ));
                }
                if subtitles[1] != "10.10.10.7 on wlo1" {
                    return Err(format!(
                        "a row without one shows address and interface alone, got `{}`",
                        subtitles[1]
                    ));
                }
                if !dialog.names_caption_is_showing() {
                    return Err(
                        "a row carries a name, so the line saying what it is shows".to_string()
                    );
                }
                Ok(())
            })();
        },
    );
    outcome.replace(Err("activation never ran".to_string()))
}

/// The negative control for the caption: with no name on any row there is
/// nothing to explain, and the line stays away.
fn nothing_explains_a_name_when_no_row_has_one() -> Result<(), String> {
    reset_book();
    let outcome: Rc<RefCell<Result<(), String>>> =
        Rc::new(RefCell::new(Err("activation never ran".to_string())));
    let seen = outcome.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.DeviceNoNames",
        move |_app| {
            let dialog = DevicesDialog::new();
            dialog.set_neighbours(&[choice("bc:24:11:5e:1c:6e", "10.10.10.245")]);
            *seen.borrow_mut() = if dialog.names_caption_is_showing() {
                Err("no row has a name, so nothing should explain one".to_string())
            } else {
                Ok(())
            };
        },
    );
    outcome.replace(Err("activation never ran".to_string()))
}

/// The whole point of this task, asserted from one end to the other: a
/// device saved by pressing the real Save button is in the real
/// `devices.toml`, and the real code path the window uses to read that file
/// then produces a target row in a real `OpenDialog`.
///
/// The MAC is not typed. It is picked, by activating a real picker row
/// exactly as a click on it does -- which is how a MAC cannot be mistyped,
/// the property `porthole devices add` has and the reason its picker exists
/// at all.
fn saving_a_device_puts_it_in_the_book_and_then_in_the_open_dialog() -> Result<(), String> {
    reset_book();
    let outcome: Rc<RefCell<Result<(), String>>> =
        Rc::new(RefCell::new(Err("activation never ran".to_string())));
    let seen = outcome.clone();
    activate("com.jacopobriccola.Porthole.Test.SaveDevice", move |_app| {
        let dialog = DevicesDialog::new();
        dialog.set_neighbours(&[choice("bc:24:11:5e:1c:6e", "10.10.10.245")]);
        dialog.set_name_text("phone");

        // A click on the row, not a MAC written into the field by this
        // test: activating an `AdwActionRow` is what a click on it does.
        let row = dialog.neighbour_row(0).expect("the picker offers a row");
        gtk::prelude::WidgetExt::activate(&row);

        let mut result = (|| {
            if dialog.mac_text() != "bc:24:11:5e:1c:6e" {
                return Err(format!(
                    "picking a row must fill the field the save reads, got {:?}",
                    dialog.mac_text()
                ));
            }
            if !dialog.neighbour_is_picked(0) {
                return Err("the picked row must be marked as picked".to_string());
            }
            if !dialog.can_save() {
                return Err(
                    "a valid name and a picked MAC must make the device saveable".to_string(),
                );
            }
            Ok(())
        })();

        if result.is_ok() {
            dialog.save_button().emit_clicked();
            if !pump_until(
                || saved_names() == vec!["phone".to_string()],
                Duration::from_secs(5),
            ) {
                result = Err(format!(
                    "the book should hold exactly `phone`, holds {:?}",
                    saved_names()
                ));
            }
        }

        if result.is_ok() {
            // The real path the window reads the book with, not a
            // reimplementation of it here.
            match window::load_devices() {
                Ok(entries) => {
                    let open = OpenDialog::new();
                    open.set_devices(&entries);
                    let labels = open.target_labels();
                    if !labels.iter().any(|l| l == "phone") {
                        result = Err(format!(
                            "the saved device must be offered as a target, got {labels:?}"
                        ));
                    }
                }
                Err(reason) => result = Err(format!("the book must load: {reason}")),
            }
        }

        *seen.borrow_mut() = result;
    });
    outcome.replace(Err("activation never ran".to_string()))
}

/// The bug this holds down was real and was fixed once already, on the CLI
/// side: `office:pc` saved cleanly and was then permanently unusable,
/// because `--to` reads a name containing `:` as a failed IP address. The
/// interface must refuse exactly what the tool refuses, in the tool's own
/// words, and nothing must reach the book.
fn a_name_the_tool_refuses_is_refused_here_too() -> Result<(), String> {
    reset_book();
    let outcome: Rc<RefCell<Result<(), String>>> =
        Rc::new(RefCell::new(Err("activation never ran".to_string())));
    let seen = outcome.clone();
    activate("com.jacopobriccola.Porthole.Test.BadName", move |_app| {
        let dialog = DevicesDialog::new();
        dialog.set_mac_text("bc:24:11:5e:1c:6e");

        let mut result = Ok(());
        for name in ["office:pc", "home/laptop", "subnet", "10.0.0.5"] {
            dialog.set_name_text(name);
            let expected = devices::validate_device_name(name)
                .expect_err("the tool refuses this name")
                .to_string();
            match dialog.name_error() {
                Some(message) if message == expected => {}
                other => {
                    result = Err(format!(
                        "`{name}` must be refused in the tool's own words ({expected:?}), \
                         got {other:?}"
                    ));
                    break;
                }
            }
            if dialog.can_save() {
                result = Err(format!("`{name}` must not be saveable"));
                break;
            }
        }

        if result.is_ok() {
            // The button is what the earlier fix turned out to hinge on:
            // an insensitive button that a press still went through would
            // have written the book anyway.
            dialog.save_button().emit_clicked();
            pump_until(|| false, Duration::from_millis(300));
            if !saved_names().is_empty() {
                result = Err(format!(
                    "nothing may reach the book, it holds {:?}",
                    saved_names()
                ));
            }
        }
        *seen.borrow_mut() = result;
    });
    outcome.replace(Err("activation never ran".to_string()))
}

/// The same, one field along: what the MAC field accepts is
/// `devices::parse_mac`, so what it refuses is that function's refusal.
fn a_mac_the_tool_refuses_is_refused_here_too() -> Result<(), String> {
    reset_book();
    let outcome: Rc<RefCell<Result<(), String>>> =
        Rc::new(RefCell::new(Err("activation never ran".to_string())));
    let seen = outcome.clone();
    activate("com.jacopobriccola.Porthole.Test.BadMac", move |_app| {
        let dialog = DevicesDialog::new();
        dialog.set_name_text("phone");

        let mut result = Ok(());
        for mac in ["not-a-mac", "bc:24:11:5e:1c", "bc-24-11-5e-1c-6e"] {
            dialog.set_mac_text(mac);
            let expected = devices::parse_mac(mac)
                .expect_err("the tool refuses this MAC")
                .to_string();
            match dialog.mac_error() {
                Some(message) if message == expected => {}
                other => {
                    result = Err(format!(
                        "`{mac}` must be refused in the tool's own words ({expected:?}), \
                         got {other:?}"
                    ));
                    break;
                }
            }
            if dialog.can_save() {
                result = Err(format!("`{mac}` must not be saveable"));
                break;
            }
        }
        *seen.borrow_mut() = result;
    });
    outcome.replace(Err("activation never ran".to_string()))
}

/// The trade the user made knowingly: a MAC typed by hand for a device that
/// is not here **is** saved, and the interface says at that moment that it
/// did not resolve -- in the resolver's own words, not a verdict this dialog
/// invented.
///
/// The expected text is computed by calling `devices::resolve` from the
/// test, so this holds whichever way resolution fails on the machine
/// running it: "not on this network right now" where `ip` exists and there
/// is no such neighbour, and the command it could not run where `ip` does
/// not (this container).
fn a_typed_mac_that_does_not_resolve_is_saved_and_said_so() -> Result<(), String> {
    reset_book();
    let outcome: Rc<RefCell<Result<(), String>>> =
        Rc::new(RefCell::new(Err("activation never ran".to_string())));
    let seen = outcome.clone();
    activate("com.jacopobriccola.Porthole.Test.TypedMac", move |_app| {
        let dialog = DevicesDialog::new();
        // Nothing on this network to pick from, which is the situation the
        // field exists for.
        dialog.set_neighbours(&[]);
        dialog.set_name_text("laptop");
        dialog.set_mac_text("12:34:56:78:9A:BC");

        let mut result = if dialog.can_save() {
            Ok(())
        } else {
            Err("a typed MAC must be saveable even with nothing to pick from".to_string())
        };

        if result.is_ok() {
            dialog.save_button().emit_clicked();
            if !pump_until(|| dialog.note().is_some(), Duration::from_secs(5)) {
                result = Err("saving must say what the re-read book makes of it".to_string());
            }
        }

        if result.is_ok() {
            // Saved, whatever the resolution said.
            let book = devices::Book::load(&book_path()).expect("the book loads");
            match book.find("laptop").map(|d| d.address.clone()) {
                // Typed in capitals, saved lower-case -- `parse_mac`'s doing,
                // not this dialog's.
                Some(devices::DeviceAddress::Mac(mac)) if mac == "12:34:56:78:9a:bc" => {}
                other => result = Err(format!("`laptop` must be in the book, got {other:?}")),
            }

            let reason = devices::resolve(&book, "laptop", &RealRunner)
                .expect_err("this device cannot resolve here")
                .to_string();
            let note = dialog.note().unwrap_or_default();
            if !note.starts_with("Saved") {
                result = Err(format!("the note must say it was saved, got {note:?}"));
            } else if !note.contains(&reason) {
                result = Err(format!(
                    "the note must carry the resolver's own words ({reason:?}), got {note:?}"
                ));
            } else if !dialog.note_is_marked() {
                result = Err("a device that did not resolve is worth marking".to_string());
            }
        }

        *seen.borrow_mut() = result;
    });
    outcome.replace(Err("activation never ran".to_string()))
}

/// An empty neighbour table and a neighbour table that could not be read
/// are two different facts, and neither renders as the other -- this
/// project's characteristic defect, one dialog further along.
fn an_unreadable_neighbour_table_is_not_an_empty_network() -> Result<(), String> {
    let outcome: Rc<RefCell<Result<(), String>>> =
        Rc::new(RefCell::new(Err("activation never ran".to_string())));
    let seen = outcome.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.NoNeighbours",
        move |_app| {
            let dialog = DevicesDialog::new();

            dialog.set_neighbours(&[]);
            let mut result =
                if dialog.neighbours_quiet_is_showing() && dialog.neighbours_trouble().is_none() {
                    Ok(())
                } else {
                    Err("an empty network is the quiet line, not the trouble note".to_string())
                };

            if result.is_ok() {
                dialog.set_neighbours_unavailable("could not run `ip -4 neigh show`");
                match dialog.neighbours_trouble() {
                    Some((_, reason)) if reason.contains("ip -4 neigh show") => {}
                    other => {
                        result = Err(format!(
                            "a failed listing must carry its own reason, got {other:?}"
                        ))
                    }
                }
                if result.is_ok() && dialog.neighbours_quiet_is_showing() {
                    result =
                        Err("a failed listing must not also read as an empty network".to_string());
                }
            }
            *seen.borrow_mut() = result;
        },
    );
    outcome.replace(Err("activation never ran".to_string()))
}

/// Every saved row carries its own way out. A GNOME app that needs a mouse
/// is not a GNOME app, so that button is checked the same way every other
/// action in this crate is.
fn every_saved_row_can_be_forgotten_from_the_keyboard() -> Result<(), String> {
    let outcome: Rc<RefCell<Result<(), String>>> =
        Rc::new(RefCell::new(Err("activation never ran".to_string())));
    let seen = outcome.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ForgetButton",
        move |_app| {
            let dialog = DevicesDialog::new();
            dialog.set_saved(&[
                SavedDevice {
                    name: "phone".to_string(),
                    address: "bc:24:11:5e:1c:6e".to_string(),
                    resolved: Ok("10.10.10.245".parse().unwrap()),
                },
                SavedDevice {
                    name: "laptop".to_string(),
                    address: "12:34:56:78:9a:bc".to_string(),
                    resolved: Err("device not reachable: `laptop` is not here".to_string()),
                },
            ]);

            let mut result = Ok(());
            if dialog.saved_labels() != vec!["phone".to_string(), "laptop".to_string()] {
                result = Err(format!(
                    "both devices must be rows, got {:?}",
                    dialog.saved_labels()
                ));
            }
            // The row that resolved says what it resolves to; the one that did
            // not carries the resolver's own sentence unaltered.
            let subtitles = dialog.saved_subtitles();
            if result.is_ok() && !subtitles[0].contains("resolves to 10.10.10.245 right now") {
                result = Err(format!("got {:?}", subtitles[0]));
            }
            if result.is_ok() && subtitles[1] != "device not reachable: `laptop` is not here" {
                result = Err(format!("got {:?}", subtitles[1]));
            }
            for index in 0..2 {
                if result.is_err() {
                    break;
                }
                match dialog.forget_button(index) {
                    Some(button) if button.is_focusable() => {}
                    other => {
                        result = Err(format!(
                            "row {index} needs a Forget button reachable by keyboard, got \
                         {:?}",
                            other.map(|b| b.is_focusable())
                        ))
                    }
                }
            }
            *seen.borrow_mut() = result;
        },
    );
    outcome.replace(Err("activation never ran".to_string()))
}

/// The button beside the open dialog's target list, pressed for real. What
/// it does is `window.rs`'s to decide -- this asserts only that the press
/// reaches the slot that dialog leaves for it.
fn the_open_dialogs_own_button_reaches_the_slot_the_window_fills() -> Result<(), String> {
    let outcome: Rc<RefCell<Result<(), String>>> =
        Rc::new(RefCell::new(Err("activation never ran".to_string())));
    let seen = outcome.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ManageButton",
        move |_app| {
            let dialog = OpenDialog::new();
            let pressed = Rc::new(Cell::new(0));
            let counted = pressed.clone();
            dialog.on_manage_devices(move || counted.set(counted.get() + 1));

            let button = dialog.manage_devices_button();
            let mut result = if button.is_focusable() {
                Ok(())
            } else {
                Err("the button must be reachable by keyboard".to_string())
            };
            if result.is_ok() && button.tooltip_text().as_deref() != Some("Save a device") {
                result = Err(format!(
                    "expected the tooltip \"Save a device\", got {:?}",
                    button.tooltip_text()
                ));
            }
            if result.is_ok() {
                button.emit_clicked();
                if pressed.get() != 1 {
                    result = Err(format!(
                        "one press must reach the slot once, reached it {} times",
                        pressed.get()
                    ));
                }
            }
            *seen.borrow_mut() = result;
        },
    );
    outcome.replace(Err("activation never ran".to_string()))
}

/// The other way in: the window's own main menu. The entry is a `gio::Menu`
/// item pointing at an action, so what is checked is that the item names
/// the action and that the window really has it -- a menu item naming an
/// action a window does not have renders insensitive and says nothing about
/// why.
fn the_main_menu_has_a_saved_devices_entry_the_window_can_answer() -> Result<(), String> {
    let outcome: Rc<RefCell<Result<(), String>>> =
        Rc::new(RefCell::new(Err("activation never ran".to_string())));
    let seen = outcome.clone();
    activate("com.jacopobriccola.Porthole.Test.MainMenu", move |app| {
        let win = PortholeWindow::new(app);
        win.present();

        // Reachability from the keyboard is checked where every other
        // action's is, in `tests/window.rs`'s own
        // `every_action_is_reachable_from_the_keyboard`, which now walks
        // this widget too. What is checked here is what that one cannot
        // see: that the menu really carries the entry, and that the window
        // really has the action the entry names.
        let menu_button = win.menu_button();
        let mut result = Ok(());

        if result.is_ok() {
            let actions: Vec<String> = match menu_button.menu_model() {
                Some(model) => (0..model.n_items())
                    .filter_map(|index| {
                        model
                            .item_attribute_value(index, "action", None)
                            .and_then(|v| v.str().map(|s| s.to_string()))
                    })
                    .collect(),
                None => Vec::new(),
            };
            if !actions.iter().any(|a| a == "win.devices") {
                result = Err(format!(
                    "the menu must carry the saved-devices entry, got {actions:?}"
                ));
            }
        }

        if result.is_ok() && !win.has_action("devices") {
            result = Err("the window must have the action its menu names".to_string());
        }

        if result.is_ok() {
            // Activated for real: this presents the saved-devices dialog
            // over the window, which is the whole of what the entry does.
            if let Err(e) = gtk::prelude::WidgetExt::activate_action(&*win, "win.devices", None) {
                result = Err(format!("the menu entry must activate: {e}"));
            }
        }

        *seen.borrow_mut() = result;
    });
    outcome.replace(Err("activation never ran".to_string()))
}

fn main() {
    // Before anything: every case below writes a real address book, and it
    // must not be the one belonging to whoever is running these tests.
    // `PORTHOLE_DEVICES_FILE` is honoured in debug builds only.
    std::env::set_var(devices::DEVICES_FILE_ENV, book_path());
    reset_book();

    type Case = (&'static str, fn() -> Result<(), String>);
    let cases: Vec<Case> = vec![
        (
            "the_close_button_dismisses_the_saved_devices_panel",
            the_close_button_dismisses_the_saved_devices_panel,
        ),
        (
            "escape_dismisses_the_saved_devices_panel",
            escape_dismisses_the_saved_devices_panel,
        ),
        (
            "the_keyboard_starts_in_the_name_field",
            the_keyboard_starts_in_the_name_field,
        ),
        (
            "saving_a_device_puts_it_in_the_book_and_then_in_the_open_dialog",
            saving_a_device_puts_it_in_the_book_and_then_in_the_open_dialog,
        ),
        (
            "a_name_the_tool_refuses_is_refused_here_too",
            a_name_the_tool_refuses_is_refused_here_too,
        ),
        (
            "a_mac_the_tool_refuses_is_refused_here_too",
            a_mac_the_tool_refuses_is_refused_here_too,
        ),
        (
            "a_typed_mac_that_does_not_resolve_is_saved_and_said_so",
            a_typed_mac_that_does_not_resolve_is_saved_and_said_so,
        ),
        (
            "an_unreadable_neighbour_table_is_not_an_empty_network",
            an_unreadable_neighbour_table_is_not_an_empty_network,
        ),
        (
            "every_saved_row_can_be_forgotten_from_the_keyboard",
            every_saved_row_can_be_forgotten_from_the_keyboard,
        ),
        (
            "the_open_dialogs_own_button_reaches_the_slot_the_window_fills",
            the_open_dialogs_own_button_reaches_the_slot_the_window_fills,
        ),
        (
            "the_main_menu_has_a_saved_devices_entry_the_window_can_answer",
            the_main_menu_has_a_saved_devices_entry_the_window_can_answer,
        ),
        (
            "a_row_shows_a_name_where_there_is_one_and_invents_none_where_there_is_not",
            a_row_shows_a_name_where_there_is_one_and_invents_none_where_there_is_not,
        ),
        (
            "nothing_explains_a_name_when_no_row_has_one",
            nothing_explains_a_name_when_no_row_has_one,
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

    let _ = std::fs::remove_file(book_path());

    if any_failed {
        std::process::exit(1);
    }
}
