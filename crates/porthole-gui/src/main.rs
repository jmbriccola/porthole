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
//! `--screenshot <path>` is the one flag this binary parses itself, ahead of
//! everything above: debug builds only, see [`run_screenshot`] and
//! `porthole_gui::screenshot`'s own module doc for what it renders and why
//! it never touches the helper or `/proc`.

use adw::prelude::*;

fn main() -> gtk::glib::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match screenshot_flag(&args) {
        Some(path) => run_screenshot(&path),
        None => porthole_gui::app::build().run(),
    }
}

/// `--screenshot <path>`'s own value, or `None` when the flag is absent.
/// Parsed by hand rather than pulling in a CLI-argument crate for one flag
/// this binary's ordinary users never see -- everyone else runs this with no
/// arguments at all, the same as any other GNOME application launched from a
/// desktop file.
fn screenshot_flag(args: &[String]) -> Option<std::path::PathBuf> {
    let index = args.iter().position(|a| a == "--screenshot")?;
    args.get(index + 1).map(std::path::PathBuf::from)
}

/// Honoured in debug builds only: a release binary rendering an arbitrary
/// path to a real, GTK-composited window with no user present to see it is
/// contrived, but free to close -- the same reasoning
/// `porthole_core::state::STATE_FILE_ENV` and `porthole-helper`'s own
/// `--session` flag are each documented as existing under.
fn run_screenshot(path: &std::path::Path) -> gtk::glib::ExitCode {
    if !cfg!(debug_assertions) {
        eprintln!(
            "porthole-gui: --screenshot exists for development and is not available in release \
             builds"
        );
        return gtk::glib::ExitCode::FAILURE;
    }
    porthole_gui::screenshot::run(path)
}
