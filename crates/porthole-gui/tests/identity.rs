//! What the running window tells the X server it is, read back off the X
//! server.
//!
//! The application id (`app::APP_ID`) is a session-bus claim and nothing
//! else; a window's `WM_CLASS` on X11 -- and its `app_id` on Wayland --
//! comes from GLib's `prgname`, which defaults to the executable's
//! basename. Those are two independent strings, and this crate shipped with
//! them different: `WM_CLASS` said `porthole-gui` while the installed entry
//! was `com.jacopobriccola.Porthole.desktop`. The application showed no
//! icon anywhere, with the SVG, the entry, the `Icon=` line, the install
//! path and the icon cache all already correct -- five right answers that
//! did not add up to one. What a window put on the X server is not
//! something this process can read back out of its own widgets, so this
//! file asks the X server instead, through `xprop`
//! (`tests/container/Containerfile.gui` installs it).
//!
//! Both sides of the comparison are read rather than typed: the expected
//! strings come from the `.desktop` file in `data/` that launches this
//! crate's own binary, and the measured ones from a real window that
//! `app::build()` -- the production constructor, not a hand-assembled
//! `adw::Application` -- put on the display.
//!
//! Its own `[[test]]` target, `harness = false`, for the reason
//! `tests/window.rs`'s module doc gives, plus one of its own:
//! `app::build()` sets `prgname`, and `prgname` is process-wide -- it is
//! the very state measured here, so it gets a process where nothing else
//! is being measured.

use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use adw::prelude::*;

/// The two strings a `.desktop` file contributes here: the stem of its own
/// filename, which is the name a desktop environment looks an entry up
/// under, and the icon name it declares.
struct DesktopEntry {
    stem: String,
    icon: String,
}

/// The entry in `data/` whose `Exec=` launches this crate's binary. Found
/// rather than named, so a rename of the file is picked up here instead of
/// leaving this test comparing a string against itself -- `data/` holds a
/// second entry (`porthole-agent.desktop`) that must not be the one
/// matched, which is why this insists on exactly one hit.
fn gui_desktop_entry() -> Result<DesktopEntry, String> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../data");
    let exec = format!("Exec={}", env!("CARGO_PKG_NAME"));
    let mut found: Vec<DesktopEntry> = Vec::new();
    let listing = std::fs::read_dir(dir).map_err(|e| format!("{dir}: {e}"))?;
    for entry in listing {
        let path = entry.map_err(|e| format!("{dir}: {e}"))?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
            continue;
        }
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if !text.lines().any(|line| line.trim() == exec) {
            continue;
        }
        let icon = text
            .lines()
            .find_map(|line| line.trim().strip_prefix("Icon="))
            .ok_or_else(|| format!("{} declares no Icon=", path.display()))?;
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("{} has no readable stem", path.display()))?;
        found.push(DesktopEntry {
            stem: stem.to_string(),
            icon: icon.to_string(),
        });
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        n => Err(format!(
            "{n} files in {dir} carry `{exec}`, expected exactly 1"
        )),
    }
}

/// What one real window reported about itself.
struct WindowIdentity {
    /// `WM_CLASS`'s two fields, in the order `xprop` prints them:
    /// instance name first, class second.
    wm_class: (String, String),
    /// GTK's process-wide icon name for the windows it draws, which is a
    /// separate setting from `WM_CLASS` and was separately unset.
    default_icon_name: Option<String>,
}

/// Measured once and shared by every case below: two `adw::Application`s
/// claiming the same id one after the other on one session bus is a
/// complication none of these checks needs.
fn identity() -> Result<&'static WindowIdentity, String> {
    static MEASURED: OnceLock<Result<WindowIdentity, String>> = OnceLock::new();
    MEASURED.get_or_init(measure).as_ref().map_err(Clone::clone)
}

/// Runs the production application -- `app::build()`, the same call
/// `main.rs` makes -- and reads its window's identity while that window is
/// still on the display.
fn measure() -> Result<WindowIdentity, String> {
    let app = porthole_gui::app::build();
    let captured = std::rc::Rc::new(std::cell::RefCell::new(None));
    let sink = captured.clone();
    // Chained onto `app::build()`'s own activate handler rather than
    // replacing it, so the window read below is the one production
    // activation presents.
    app.connect_activate(move |app| {
        sink.replace(Some(capture(app)));
        app.quit();
    });
    app.run_with_args::<&str>(&[]);
    let captured = captured.borrow_mut().take();
    captured.unwrap_or_else(|| Err("the application never activated".to_string()))
}

fn capture(app: &adw::Application) -> Result<WindowIdentity, String> {
    let window = app
        .active_window()
        .ok_or_else(|| "activation presented no window".to_string())?;
    let title = window
        .title()
        .ok_or_else(|| "the window has no title for xprop to find it by".to_string())?
        .to_string();
    Ok(WindowIdentity {
        wm_class: read_wm_class(&title, Duration::from_secs(10))?,
        default_icon_name: gtk::Window::default_icon_name().map(|name| name.to_string()),
    })
}

/// `WM_CLASS` as the X server holds it, for the window `xprop` finds by
/// title. Retried until `timeout`: presenting a window is a request to the
/// server, and the property is there only once the server has acted on it.
/// A missing `xprop`, an unreachable display and a window that never
/// appears all end as an error rather than as an absent measurement -- a
/// check that silently measures nothing is the failure mode this whole
/// file exists to close.
fn read_wm_class(title: &str, timeout: Duration) -> Result<(String, String), String> {
    let deadline = Instant::now() + timeout;
    loop {
        pump_main_context();
        if let Some(display) = gtk::gdk::Display::default() {
            display.flush();
        }
        let output = Command::new("xprop")
            .args(["-name", title, "WM_CLASS"])
            .output()
            .map_err(|e| {
                format!(
                    "could not run xprop, which tests/container/Containerfile.gui \
                     installs: {e}"
                )
            })?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = stdout.lines().find(|l| l.starts_with("WM_CLASS(")) {
            let fields: Vec<String> = line
                .split('"')
                .skip(1)
                .step_by(2)
                .map(str::to_string)
                .collect();
            if let [instance, class] = fields.as_slice() {
                return Ok((instance.clone(), class.clone()));
            }
            return Err(format!("could not read two fields out of: {line}"));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "xprop never reported WM_CLASS for the window titled {title:?}; \
                 stdout: {stdout}stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
}

fn pump_main_context() {
    let context = gtk::glib::MainContext::default();
    for _ in 0..50 {
        while context.iteration(false) {}
    }
}

/// The defect this file was written for. A desktop environment looks an
/// application's entry up by the class its window announces; the window
/// announced the executable's basename and the entry is named after the
/// application id, and every other link in that chain -- a renderable SVG,
/// a valid entry, a matching `Icon=`, the right install path, a refreshed
/// icon cache -- was already correct and could not compensate.
fn the_windows_class_is_the_name_of_the_shipped_desktop_entry() -> Result<(), String> {
    let entry = gui_desktop_entry()?;
    let (instance, class) = &identity()?.wm_class;
    if instance == &entry.stem && class == &entry.stem {
        return Ok(());
    }
    Err(format!(
        "the window reports WM_CLASS {instance:?}, {class:?}; the shipped entry is \
         {}.desktop",
        entry.stem
    ))
}

/// `WM_CLASS` is what a desktop environment reads; GTK's own default icon
/// name is what the toolkit puts on the windows it draws. They are set
/// separately and were both wrong, so both are checked.
fn gtks_default_icon_name_is_the_one_the_desktop_entry_declares() -> Result<(), String> {
    let entry = gui_desktop_entry()?;
    match &identity()?.default_icon_name {
        Some(name) if name == &entry.icon => Ok(()),
        Some(name) => Err(format!(
            "GTK's default icon name is {name:?}; the entry declares Icon={}",
            entry.icon
        )),
        None => Err(format!(
            "GTK has no default icon name for its windows; the entry declares Icon={}",
            entry.icon
        )),
    }
}

/// One named check, the same shape every other `harness = false` target in
/// this crate uses -- an alias rather than the inline type for the reason
/// `tests/window.rs`'s own alias carries: clippy's `type_complexity` fires
/// on the inline form.
type Case = (&'static str, fn() -> Result<(), String>);

fn main() {
    let cases: [Case; 2] = [
        (
            "the_windows_class_is_the_name_of_the_shipped_desktop_entry",
            the_windows_class_is_the_name_of_the_shipped_desktop_entry,
        ),
        (
            "gtks_default_icon_name_is_the_one_the_desktop_entry_declares",
            gtks_default_icon_name_is_the_one_the_desktop_entry_declares,
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
