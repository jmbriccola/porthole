//! porthole-gui: the GTK4/libadwaita front end.
//!
//! Two different D-Bus buses, and it is deliberate that they share a name
//! (`com.jacopobriccola.Porthole`) without being the same bus -- see
//! `app.rs`'s own module doc for why. The `adw::Application` this binary
//! builds claims that name on the **session** bus, purely as its own
//! single-instance identity; every actual call to the helper (`open_now.rs`,
//! `open_dialog.rs`, `window.rs`'s own initial-load and refresh path) goes
//! over the **system** bus instead, the same bus the CLI reaches the helper
//! on by default (`porthole-cli/src/client.rs`). Every one of those calls
//! reaches the helper only through its `com.jacopobriccola.Porthole1`
//! interface (`porthole_core::ipc`) -- never a rule composed in this crate,
//! and never a firewall command run by this crate's own process.
//!
//! `--screenshot <path>`, `--screenshot-dialog <path>` and
//! `--screenshot-devices <path>` are the only flags this binary parses
//! itself, ahead of everything above: debug builds only, see
//! [`run_screenshot`] and `porthole_gui::screenshot`'s own module doc for
//! what they render and why none of them touches the helper or `/proc`.

use adw::prelude::*;

fn main() -> gtk::glib::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if let Some(path) = flag_value(&args, "--screenshot") {
        return run_screenshot("--screenshot", porthole_gui::screenshot::run, &path);
    }
    if let Some(path) = flag_value(&args, "--screenshot-dialog") {
        return run_screenshot(
            "--screenshot-dialog",
            porthole_gui::screenshot::run_dialog,
            &path,
        );
    }
    if let Some(path) = flag_value(&args, "--screenshot-devices") {
        return run_screenshot(
            "--screenshot-devices",
            porthole_gui::screenshot::run_devices,
            &path,
        );
    }
    porthole_gui::app::build().run()
}

/// The value after `flag`, or `None` when the flag is absent. Matched
/// exactly, so `--screenshot` does not swallow `--screenshot-dialog` or
/// `--screenshot-devices`. Parsed by hand rather than pulling in a
/// CLI-argument crate for three flags this binary's ordinary users never
/// see -- everyone else runs this with no arguments at
/// all, the same as any other GNOME application launched from a desktop
/// file.
fn flag_value(args: &[String], flag: &str) -> Option<std::path::PathBuf> {
    let index = args.iter().position(|a| a == flag)?;
    args.get(index + 1).map(std::path::PathBuf::from)
}

/// Honoured in debug builds only: a release binary rendering an arbitrary
/// path to a real, GTK-composited window with no user present to see it is
/// contrived, but free to close -- the same reasoning
/// `porthole_core::state::STATE_FILE_ENV` and `porthole-helper`'s own
/// `--session` flag are each documented as existing under.
fn run_screenshot(
    flag: &str,
    render: impl Fn(&std::path::Path) -> gtk::glib::ExitCode,
    path: &std::path::Path,
) -> gtk::glib::ExitCode {
    if !cfg!(debug_assertions) {
        eprintln!(
            "porthole-gui: {flag} exists for development and is not available in release builds"
        );
        return gtk::glib::ExitCode::FAILURE;
    }
    render(path)
}
