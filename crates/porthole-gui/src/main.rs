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

use adw::prelude::*;

fn main() -> gtk::glib::ExitCode {
    porthole_gui::app::build().run()
}
