//! porthole-gui: the GTK4/libadwaita front end.
//!
//! No D-Bus code exists in this crate yet -- `zbus` and `tokio` are declared
//! dependencies with nothing calling them, here only for the tasks that
//! follow this one. The binding invariant those tasks must hold, stated here
//! as the forward requirement it is rather than as present-tense behaviour
//! this crate does not yet have: the GUI is to be a **session-bus client**,
//! exactly like the CLI (see `porthole-cli/src/client.rs`) -- it must reach
//! `com.jacopobriccola.Porthole` only through the helper's
//! `com.jacopobriccola.Porthole1` interface (`porthole_core::ipc`), never
//! touch the system bus directly, and never run a firewall command of its
//! own.

use adw::prelude::*;

fn main() -> gtk::glib::ExitCode {
    porthole_gui::app::build().run()
}
