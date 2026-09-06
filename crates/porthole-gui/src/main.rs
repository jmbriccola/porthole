//! porthole-gui: the GTK4/libadwaita front end.
//!
//! A session-bus client, exactly like the CLI (see
//! `porthole-cli/src/client.rs`): it reaches `com.jacopobriccola.Porthole`
//! only through the helper's `com.jacopobriccola.Porthole1` interface
//! (`porthole_core::ipc`), never touches the system bus directly, and never
//! runs a firewall command of its own.

use adw::prelude::*;

fn main() -> gtk::glib::ExitCode {
    porthole_gui::app::build().run()
}
