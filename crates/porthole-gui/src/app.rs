//! Builds the single `adw::Application` the process runs.

use adw::prelude::*;

use crate::window::PortholeWindow;

/// Both the GTK application id and the helper's well-known D-Bus name are
/// `com.jacopobriccola.Porthole` (see `porthole_core::ipc::SERVICE`), but
/// they are not the same name on the same bus. This id is a single-instance
/// claim `adw::Application` makes on the **session** bus; the helper's
/// production name lives on the **system** bus (`porthole-helper` serves
/// there unless started with the test-only `--session` flag, which claims
/// the identical name on the session bus instead -- see
/// `porthole-helper/src/main.rs`). So the two do not collide in production,
/// and this crate's own container tests never start a helper at all, so
/// they cannot collide with one either.
pub const APP_ID: &str = "com.jacopobriccola.Porthole";

/// Constructs the application and wires its one window. Splitting this out
/// of `main` is what lets a test build the exact same activation path
/// (`app::build().run()` in production) instead of only ever exercising a
/// hand-assembled `PortholeWindow` -- see
/// `applications_own_activation_handler_also_realizes_a_window` in
/// `tests/window.rs`.
pub fn build() -> adw::Application {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(|app| {
        let window = PortholeWindow::new(app);
        window.present();
    });
    app
}
