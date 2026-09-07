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
///
/// [`build`] also uses this string for two things that are not bus names at
/// all: the window's own `WM_CLASS`/`app_id`, and GTK's icon name for the
/// windows it draws. See that function's own comments.
pub const APP_ID: &str = "com.jacopobriccola.Porthole";

/// Constructs the application and wires its one window. Splitting this out
/// of `main` is what lets a test build the exact same activation path
/// (`app::build().run()` in production) instead of only ever exercising a
/// hand-assembled `PortholeWindow` -- see
/// `applications_own_activation_handler_also_realizes_a_window` in
/// `tests/window.rs`, and `tests/identity.rs` for the two names below.
pub fn build() -> adw::Application {
    // `application_id` below names the application on the session bus and
    // nothing else. A window's `WM_CLASS` on X11 and its `app_id` on
    // Wayland come from GLib's `prgname`, which is the executable's
    // basename unless something sets it -- so without this line the window
    // announced itself as `porthole-gui` while the entry installed
    // alongside it was named `com.jacopobriccola.Porthole.desktop`. The
    // application showed no icon anywhere -- not in an app grid, not in a
    // dock, on neither Wayland nor X11 -- with the SVG, the entry, the
    // `Icon=` line, the install path and the icon cache all already
    // correct. Set before the application runs; `tests/identity.rs` reads
    // what the window then reports back off the X server.
    gtk::glib::set_prgname(Some(APP_ID));
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(|app| {
        // GTK's own icon name for the windows it draws: a third setting
        // again, separate from the bus name and from `WM_CLASS`, and
        // measured unset before this line. Here rather than beside
        // `set_prgname` above because gtk4-rs asserts GTK is initialized
        // before this call, and `build()` returns before `run()`
        // initializes it.
        gtk::Window::set_default_icon_name(APP_ID);
        let window = PortholeWindow::new(app);
        window.present();
    });
    app
}
