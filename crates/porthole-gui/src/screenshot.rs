//! `main.rs`'s three debug-only screenshot flags.
//!
//! `--screenshot <path>` ([`run`]) populates a real [`PortholeWindow`] with
//! invented data, renders exactly what GTK is currently displaying, saves
//! that to `path` as a PNG, and exits. `docs/screenshot.png` is its output.
//!
//! `--screenshot-dialog <path>` ([`run_dialog`]) does the same for the open
//! dialog, the Docker explanation it presents before opening a
//! Docker-managed port, and the same dialog making the other request --
//! three images, since only one of them can be in front at a time. Nothing
//! in the repository is their output; they exist so a change to the dialog
//! can be looked at, which is how this project found a truncated row, a
//! window forced wide by a single unwrapped line, and an unmarked "open to
//! anyone" that no test had caught.
//!
//! `--screenshot-devices <path>` ([`run_devices`]) renders the saved-devices
//! dialog three times: populated, on a machine with nothing saved and
//! nothing seen on the network, and after a MAC typed by hand for a device
//! that is not here. That third image drives the real Save button and so
//! writes a real address book, which is why it is rendered only when
//! `PORTHOLE_DEVICES_FILE` names one.
//!
//! **Fixture data, never live data.** [`run`] never lets a live helper round
//! trip or a `/proc` scan touch the window at all --
//! [`PortholeWindow::new_without_initial_load`] is what makes that true,
//! rather than [`PortholeWindow::new`] plus a hope that the fixture setters
//! below win whatever race they would otherwise be in against the real
//! ones. That constructor also starts no subscription to the helper's
//! announcements, so nothing can arrive later and re-read over the fixture
//! either. Either real source would be the wrong picture for this flag's own
//! purpose: the container this runs in has no `porthole-helper` and nothing
//! open, so a live read would screenshot an empty window, and `/proc` in
//! that same container reflects whatever this milestone's own test process
//! happens to have listening, not a machine anyone chose to show.
//!
//! The fixture below is invented, not measured: no number in it was read off
//! a real machine, and nothing here draws on one that was. It reuses the
//! port numbers and addresses this project's own README and
//! `docs/json-schema.md` already use as examples (`5173/tcp`,
//! `10.10.10.0/24`, `firewalld 2.4.4`), so the screenshot reads as the same
//! running example the rest of the documentation already shows, not a new
//! one invented just for this image. The saved devices [`fixture_devices`]
//! invents are the exception, having no counterpart in the documentation:
//! one of them does not resolve, and one has a name long enough to show
//! what an arbitrary one does to the dialog's layout.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use adw::prelude::*;

use porthole_core::clock::{Clock, SystemClock};
use porthole_core::docker::Published;
use porthole_core::ipc::{WireRule, WireStatus};
use porthole_core::listening::{Binding, Service};
use porthole_core::model::Protocol;

use crate::devices_dialog::{DevicesDialog, NeighbourChoice, SavedDevice};
use crate::open_dialog::{DeviceEntry, OpenDialog};
use crate::window::PortholeWindow;

/// A session-bus application id distinct from the real one (`crate::app::APP_ID`)
/// and from every id `tests/window.rs` claims for itself, so a `--screenshot`
/// run sharing a session bus with anything else this milestone starts never
/// collides with it.
const APP_ID: &str = "com.jacopobriccola.Porthole.Screenshot";

/// [`run_dialog`]'s own id, for the same reason -- the two flags can be run
/// one after the other on the same session bus.
const DIALOG_APP_ID: &str = "com.jacopobriccola.Porthole.ScreenshotDialog";

/// [`run_devices`]'s own id, for the same reason again.
const DEVICES_APP_ID: &str = "com.jacopobriccola.Porthole.ScreenshotDevices";

/// Three open rules: one mid-countdown towards the current subnet, one
/// towards "anyone" and until reboot -- between them, both scope words
/// `open_now.rs` renders and both of the two ways it renders a remaining
/// duration -- and one that redirects rather than permits, which is the
/// only row shape carrying an address and two ports on top of all that.
fn fixture_rules() -> Vec<WireRule> {
    let now = SystemClock.now();
    vec![
        WireRule {
            id: "5173/tcp".to_string(),
            port: 5173,
            protocol: "tcp".to_string(),
            target: "10.10.10.0/24".to_string(),
            scope: "network".to_string(),
            backend: "firewalld".to_string(),
            opened_at: now.saturating_sub(600),
            expires_at: now + 1_800,
            uid: 1000,
            // Not a forward: an empty address is what says so.
            container_addr: String::new(),
            container_port: 0,
            published_port: 0,
        },
        WireRule {
            id: "8080/tcp".to_string(),
            port: 8080,
            protocol: "tcp".to_string(),
            target: "anywhere".to_string(),
            scope: "anywhere".to_string(),
            backend: "firewalld".to_string(),
            opened_at: now.saturating_sub(60),
            expires_at: 0, // the wire's own until-reboot sentinel
            uid: 1000,
            // Not a forward: an empty address is what says so.
            container_addr: String::new(),
            container_port: 0,
            published_port: 0,
        },
        // The third kind of row: one that redirects rather than permits.
        // Its own three numbers are the longest thing this section renders
        // -- an address and two ports on top of the target -- which is the
        // case a picture is for.
        WireRule {
            id: "8443/tcp".to_string(),
            port: 8443,
            protocol: "tcp".to_string(),
            target: "10.10.10.0/24".to_string(),
            scope: "network".to_string(),
            backend: "firewalld".to_string(),
            opened_at: now.saturating_sub(120),
            expires_at: now + 3_300,
            uid: 1000,
            container_addr: "172.18.0.2".to_string(),
            container_port: 8080,
            published_port: 3000,
        },
    ]
}

/// Seven listening services, one of each thing `listening_section.rs` can
/// render: a network-facing one already open above (so its own "already
/// open" wording shows, not a second Open button for a port `fixture_rules`
/// already opened); a network-facing one still actionable; one published by
/// a container on every interface, which [`fixture_docker`] then marks and
/// which is offered no forward; one published by a container on loopback
/// only, which is the one shape that *is* offered one; one reachable only
/// over IPv6 (`Binding::BeyondReach`, the warning icon); and two
/// loopback-only ones, one with a resolved process name and one without,
/// the same distinction `porthole listen`'s own module doc measures as the
/// common case on an ordinary desktop.
fn fixture_services() -> Vec<Service> {
    let beyond_reach_addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
    vec![
        Service {
            port: 5173,
            protocol: Protocol::Tcp,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            binding: Binding::AllInterfaces,
            process: Some("node".to_string()),
            pid: Some(12043),
        },
        Service {
            port: 4000,
            protocol: Protocol::Tcp,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            binding: Binding::AllInterfaces,
            process: None,
            pid: None,
        },
        Service {
            port: 9000,
            protocol: Protocol::Tcp,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            binding: Binding::AllInterfaces,
            process: Some("docker-proxy".to_string()),
            pid: Some(3117),
        },
        Service {
            port: 22,
            protocol: Protocol::Tcp,
            address: IpAddr::V6(beyond_reach_addr),
            binding: Binding::BeyondReach(beyond_reach_addr),
            process: Some("sshd".to_string()),
            pid: Some(842),
        },
        Service {
            port: 3000,
            protocol: Protocol::Tcp,
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            binding: Binding::LoopbackOnly,
            process: Some("docker-proxy".to_string()),
            pid: Some(3118),
        },
        Service {
            port: 46715,
            protocol: Protocol::Tcp,
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            binding: Binding::LoopbackOnly,
            process: Some("code".to_string()),
            pid: Some(9816),
        },
        Service {
            port: 53,
            protocol: Protocol::Tcp,
            address: "127.0.0.53".parse().unwrap(),
            binding: Binding::LoopbackOnly,
            process: None,
            pid: None,
        },
    ]
}

/// Two published container ports, matching the two `docker-proxy` services
/// in [`fixture_services`] so the marker and the published address have
/// real rows to land on. Invented, like everything else here; the shapes
/// are what `porthole_core::docker::parse_docker_chain` produces for a
/// `-p 0.0.0.0:9000:80` and a `-p 127.0.0.1:3000:8080` publish.
fn fixture_docker() -> Vec<Published> {
    vec![
        Published {
            host_addr: None,
            host_port: 9000,
            protocol: Protocol::Tcp,
            container_addr: "172.17.0.2".parse().unwrap(),
            container_port: 80,
        },
        // The second one is what `-p 127.0.0.1:3000:8080` writes, and it is
        // the only shape a row can be forwarded from -- so the Forward
        // button has a row to appear on. The 9000 rule above is published
        // on every interface, which is exactly the case that is offered no
        // forward, so both answers are in the picture.
        Published {
            host_addr: Some(Ipv4Addr::LOCALHOST),
            host_port: 3000,
            protocol: Protocol::Tcp,
            container_addr: "172.18.0.2".parse().unwrap(),
            container_port: 8080,
        },
    ]
}

/// Three saved devices: two that resolve and one that does not, so the
/// dialog's own unselectable row and its reason are both on screen. The
/// second name is deliberately long -- a device name is whatever a person
/// typed into `devices.toml`, and this is where a layout that cannot take
/// one shows itself.
fn fixture_devices() -> Vec<DeviceEntry> {
    vec![
        DeviceEntry {
            name: "phone".to_string(),
            resolved: Ok("10.10.10.245".parse().unwrap()),
        },
        DeviceEntry {
            name: "living room television (the big one)".to_string(),
            resolved: Ok("10.10.10.31".parse().unwrap()),
        },
        DeviceEntry {
            name: "laptop".to_string(),
            // What `porthole_core::devices::resolve` actually hands a
            // caller: an `Error`'s own rendered form, prefix included.
            resolved: Err(
                "device not reachable: `laptop` (bc:24:11:5e:1c:6e) is not on \
                           this network right now"
                    .to_string(),
            ),
        },
    ]
}

/// An installed, enforcing firewalld, the same backend and version
/// `docs/json-schema.md` and `tests/window.rs`'s own fixtures already use as
/// their running example.
fn fixture_status() -> WireStatus {
    WireStatus {
        backend: "firewalld".to_string(),
        firewall_available: true,
        firewall_active: true,
        firewall_active_unknown: false,
        firewall_version: "2.4.4".to_string(),
        // Not read by anything this fixture exercises (StatusBar's active
        // branch never shows it -- see `status_bar.rs`'s own `set_status`),
        // but `WireStatus::detail` (added to carry `porthole-core`'s own
        // `BackendHealth::detail` across the wire) has no default and this
        // call site has to set something.
        detail: "firewalld is active and enforcing".to_string(),
        location: "FedoraWorkstation".to_string(),
        interface: "wlo1".to_string(),
        address: "10.10.10.119".to_string(),
        cidr: "10.10.10.0/24".to_string(),
        rules: fixture_rules(),
    }
}

/// Runs pending GLib main-context iterations so the layout pass GTK needs
/// before a widget's real allocated size means anything actually happens --
/// `present()` alone does not run it, the same gap `tests/window.rs`'s own
/// `pump_main_context` documents and works around, duplicated here rather
/// than shared because that file is a separate `harness = false` integration
/// test binary this library crate cannot depend on.
fn pump_main_context() {
    let context = gtk::glib::MainContext::default();
    for _ in 0..50 {
        while context.iteration(false) {}
    }
}

/// [`pump_main_context`], but also letting real time pass between rounds.
///
/// Presenting an `adw::Dialog` asks the whole window for a fresh layout,
/// and that one arrives on the frame clock, which non-blocking main-context
/// iterations alone do not advance: capturing straight after a `present()`
/// hit GTK's own "Trying to snapshot AdwDialogHost without a current
/// allocation" and produced no render node at all. Sleeping on this thread
/// is exactly what a real application must never do, and exactly what this
/// debug-only flag needs -- there is no user waiting on this main loop.
fn settle() {
    for _ in 0..10 {
        pump_main_context();
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    pump_main_context();
}

/// Renders `win` exactly as GTK is currently displaying it and writes the
/// result to `path` as a PNG.
///
/// `WidgetExt::snapshot_child` is the same recursive call a container
/// widget's own `snapshot` vfunc uses to paint one of its children --
/// applying that child's real transform and clip, then recursing into it --
/// invoked here on `content`'s own actual GTK parent, into a fresh
/// `gtk::Snapshot`. It has to be the *actual* parent: `win` itself does not
/// work here, and fails a GTK assertion
/// (`_gtk_widget_get_parent(child) == widget`) if tried, because libadwaita
/// does not parent the window's "content" property straight onto the plain
/// `ApplicationWindow` `win` derefs to -- confirmed directly, while writing
/// this function, by printing `content.parent()`'s own GObject type name:
/// an internal `AdwBreakpointBin`, not `win`. `content.parent()` reads
/// whatever that real parent actually is rather than this function assuming
/// or hardcoding it, so a future libadwaita version interposing a different
/// widget there costs nothing here.
///
/// The window's own `gsk::Renderer` -- reached through its `gtk::Native`,
/// since only a realized native surface has one -- then turns the resulting
/// `gsk::RenderNode` into a real `gdk::Texture`.
fn capture(win: &PortholeWindow, path: &Path) -> Result<(), String> {
    // `AdwApplicationWindowExt::content`, explicitly, not
    // `PortholeWindow::content` (the Tasks 3-6 layout box `content()`
    // ordinarily resolves to on a `PortholeWindow` -- an entirely different,
    // smaller widget nested inside this one, whose own screenshot would
    // exclude the header bar, banner and bottom status line entirely). This
    // is the `adw::ToolbarView` that gives the window its content as a
    // whole.
    let content = AdwApplicationWindowExt::content(&**win)
        .ok_or_else(|| "the window has no content widget to render".to_string())?;
    render_to_png(win, &content, path)
}

/// [`capture`], but rendering from as high in the window as
/// `snapshot_child` can reach: the window's own single direct child.
/// An `adw::Dialog` is presented into a host libadwaita interposes *above*
/// the content widget [`capture`] renders, so a dialog on screen is
/// simply not in that snapshot at all; this one contains it.
///
/// The climb reads the real widget tree rather than naming the widgets
/// libadwaita happens to interpose today -- `capture`'s own comment records
/// one of them (`AdwBreakpointBin`) already changing what `content.parent()`
/// is.
fn capture_with_dialogs(win: &PortholeWindow, path: &Path) -> Result<(), String> {
    let content = AdwApplicationWindowExt::content(&**win)
        .ok_or_else(|| "the window has no content widget to render".to_string())?;
    let mut widget: gtk::Widget = content.upcast();
    loop {
        let Some(parent) = widget.parent() else { break };
        // A widget with no parent of its own is the window: stop one step
        // below it, since `snapshot_child` renders a child *from* its
        // parent.
        if parent.parent().is_none() {
            break;
        }
        widget = parent;
    }
    render_to_png(win, &widget, path)
}

/// Renders `widget` from its own real parent and writes the result to
/// `path`. Split out of [`capture`] so [`capture_with_dialogs`] can render a
/// different widget the identical way.
fn render_to_png(win: &PortholeWindow, widget: &gtk::Widget, path: &Path) -> Result<(), String> {
    let parent = widget
        .parent()
        .ok_or_else(|| "the widget has no parent to render it from".to_string())?;

    let snapshot = gtk::Snapshot::new();
    parent.snapshot_child(widget, &snapshot);
    let node = snapshot
        .to_node()
        .ok_or_else(|| "the window produced no render node".to_string())?;

    let renderer = win
        .native()
        .and_then(|native| native.renderer())
        .ok_or_else(|| "the window's native surface has no renderer".to_string())?;

    let texture = renderer.render_texture(&node, None);
    texture
        .save_to_png(path)
        .map_err(|e| format!("could not save {}: {e}", path.display()))
}

/// Builds a real [`PortholeWindow`], fills it with the fixture data above --
/// never a live helper round trip or a `/proc` scan, either of which this
/// container could answer for real: an empty machine would screenshot a
/// window with nothing in it, and a real machine's own listening services
/// would leak onto the image this flag exists to put in the README.
/// Presents it, waits for GTK's own layout pass, renders it, and exits.
pub fn run(path: &Path) -> gtk::glib::ExitCode {
    let app = adw::Application::builder().application_id(APP_ID).build();
    let path = path.to_path_buf();
    let outcome = std::rc::Rc::new(std::cell::Cell::new(gtk::glib::ExitCode::FAILURE));
    let outcome_for_activate = outcome.clone();

    app.connect_activate(move |app| {
        let win = PortholeWindow::new_without_initial_load(app);

        let rules = fixture_rules();
        let open_ports: Vec<u16> = rules.iter().map(|r| r.port).collect();
        win.open_now().set_rules(&rules);
        win.listening().set_services(&fixture_services());
        win.listening().set_open_ports(&open_ports);
        win.listening().set_docker_ports(&fixture_docker());
        win.status_bar().set_status(&fixture_status());

        // Taller than `PortholeWindow::build`'s own 480x560 default: this
        // flag's own fixture data -- three "Open now" rows plus seven
        // "Listening" ones, deliberately one of every state those sections
        // can render -- does not fit the ordinary default without the
        // `gtk::ScrolledWindow` around them scrolling, which would leave the
        // screenshot cutting the last row off mid-way rather than showing
        // what this flag exists to show. `set_default_size` before the
        // first `present()`, never after -- see `window.rs`'s own module
        // doc on why a breakpoint (and, the same way, an allocation) only
        // ever reflects a size set before that first `present()`.
        win.set_default_size(480, 860);
        win.present();
        pump_main_context();

        match capture(&win, &path) {
            Ok(()) => {
                eprintln!("porthole-gui: wrote a screenshot to {}", path.display());
                outcome_for_activate.set(gtk::glib::ExitCode::SUCCESS);
            }
            Err(message) => eprintln!("porthole-gui: --screenshot failed: {message}"),
        }
        app.quit();
    });

    app.run_with_args::<&str>(&[]);
    outcome.get()
}

/// `main.rs`'s debug-only `--screenshot-dialog <path>` flag: the same
/// fixture window as [`run`], with an [`OpenDialog`] presented over it --
/// saved devices in its target list, and the Docker list that makes its
/// "Open Anyway" explanation appear. Writes three images: `path` for the
/// dialog itself, `<stem>-alert` for the Docker explanation on top of it
/// (a second dialog over the first, which one snapshot cannot show),
/// and `<stem>-forward` for [`OpenDialog::for_forward`] -- the same widgets
/// sending the other request, which is the image that shows whether the two
/// can be told apart.
///
/// Neither one is `docs/screenshot.png`. This exists so a change to the
/// dialog can be *looked at*, which is how this project found a truncated
/// row, a window forced wide by one unwrapped line, and an unmarked "open
/// to anyone" that no test had caught.
pub fn run_dialog(path: &Path) -> gtk::glib::ExitCode {
    let app = adw::Application::builder()
        .application_id(DIALOG_APP_ID)
        .build();
    let path = path.to_path_buf();
    let outcome = std::rc::Rc::new(std::cell::Cell::new(gtk::glib::ExitCode::FAILURE));
    let outcome_for_activate = outcome.clone();

    app.connect_activate(move |app| {
        let win = PortholeWindow::new_without_initial_load(app);

        let rules = fixture_rules();
        let open_ports: Vec<u16> = rules.iter().map(|r| r.port).collect();
        win.open_now().set_rules(&rules);
        win.listening().set_services(&fixture_services());
        win.listening().set_open_ports(&open_ports);
        win.listening().set_docker_ports(&fixture_docker());
        win.status_bar().set_status(&fixture_status());

        // `PortholeWindow::build`'s own default width, deliberately: a
        // dialog this flag renders in a window wider than the one a user
        // gets is a picture of a layout nobody sees. It was 700 px wide
        // while the dialog's minimum width was 606 and libadwaita clipped
        // it -- warning `AdwFloatingSheet exceeds AdwBreakpointBin width` --
        // in anything narrower. Measured in the container after the
        // duration chips were made to reflow: that minimum is 160 px. Taller
        // than the default, though, for the same reason [`run`]'s window is:
        // this flag's fixture fills the window behind the dialog.
        win.set_default_size(480, 820);
        win.present();
        pump_main_context();

        let dialog = OpenDialog::for_port(9000);
        dialog.set_current_network("10.10.10.0/24".parse().unwrap());
        dialog.set_devices(&fixture_devices());
        dialog.set_docker_ports(&fixture_docker());
        dialog.present(Some(&*win));
        settle();

        let dialog_ok = match capture_with_dialogs(&win, &path) {
            Ok(()) => {
                eprintln!("porthole-gui: wrote a screenshot to {}", path.display());
                true
            }
            Err(message) => {
                eprintln!("porthole-gui: --screenshot-dialog failed: {message}");
                false
            }
        };

        // The same alert pressing Open would present, built by the same
        // function the click handler calls -- not a lookalike assembled
        // here. Held in a variable rather than matched on in place, so the
        // third image below can close this exact presented alert instead of
        // building a second one that was never on screen.
        let presented_alert = dialog.docker_alert();
        let alert_ok = match &presented_alert {
            Some(alert) => {
                // Over the open dialog, which is what the Open button's own
                // handler presents it over -- not over the window, which
                // would place it somewhere no user ever sees it.
                alert.present(Some(dialog.dialog()));
                settle();
                let alert_path = beside(&path, "alert");
                match capture_with_dialogs(&win, &alert_path) {
                    Ok(()) => {
                        eprintln!(
                            "porthole-gui: wrote a screenshot to {}",
                            alert_path.display()
                        );
                        true
                    }
                    Err(message) => {
                        eprintln!("porthole-gui: --screenshot-dialog failed: {message}");
                        false
                    }
                }
            }
            None => {
                eprintln!(
                    "porthole-gui: --screenshot-dialog: the fixture produced no Docker \
                     explanation to render"
                );
                false
            }
        };

        // The third image: the same dialog making the other request. It is
        // rendered from a closed screen rather than on top of the two
        // above, so what it shows is the dialog a Forward button actually
        // presents and nothing else.
        if let Some(alert) = &presented_alert {
            alert.close();
        }
        dialog.dialog().close();
        settle();
        let forwarding = OpenDialog::for_forward(3000);
        forwarding.set_current_network("10.10.10.0/24".parse().unwrap());
        forwarding.set_devices(&fixture_devices());
        forwarding.set_docker_ports(&fixture_docker());
        forwarding.present(Some(&*win));
        settle();
        let forward_path = beside(&path, "forward");
        let forward_ok = match capture_with_dialogs(&win, &forward_path) {
            Ok(()) => {
                eprintln!(
                    "porthole-gui: wrote a screenshot to {}",
                    forward_path.display()
                );
                true
            }
            Err(message) => {
                eprintln!("porthole-gui: --screenshot-dialog failed: {message}");
                false
            }
        };

        if dialog_ok && alert_ok && forward_ok {
            outcome_for_activate.set(gtk::glib::ExitCode::SUCCESS);
        }
        app.quit();
    });

    app.run_with_args::<&str>(&[]);
    outcome.get()
}

/// Three saved devices as the devices dialog renders them: one that
/// resolves, one with a name long enough to show what an arbitrary one does
/// to a row, and one that does not resolve -- carrying
/// `porthole_core::devices::resolve`'s own sentence, which is the sentence a
/// typed MAC for a switched-off device produces.
fn fixture_saved_devices() -> Vec<SavedDevice> {
    vec![
        SavedDevice {
            name: "phone".to_string(),
            address: "bc:24:11:5e:1c:6e".to_string(),
            resolved: Ok("10.10.10.245".parse().unwrap()),
        },
        SavedDevice {
            name: "living room television (the big one)".to_string(),
            address: "aa:bb:cc:dd:ee:ff".to_string(),
            resolved: Ok("10.10.10.31".parse().unwrap()),
        },
        SavedDevice {
            name: "laptop".to_string(),
            address: "12:34:56:78:9a:bc".to_string(),
            resolved: Err(
                "device not reachable: `laptop` (12:34:56:78:9a:bc) is not on \
                           this network right now"
                    .to_string(),
            ),
        },
    ]
}

/// What the picker offers when this machine has seen something: the same
/// address and interface the rest of this project's examples use.
fn fixture_neighbours() -> Vec<NeighbourChoice> {
    vec![
        NeighbourChoice {
            mac: "bc:24:11:5e:1c:6e".to_string(),
            address: "10.10.10.245".parse().unwrap(),
            interface: "wlo1".to_string(),
            name: Some("phone.example".to_string()),
        },
        NeighbourChoice {
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            address: "10.10.10.31".parse().unwrap(),
            interface: "wlo1".to_string(),
            name: Some("_gateway".to_string()),
        },
        // The third has no name, so the picture shows both shapes of row --
        // a resolver answering nothing is ordinary, not an error state.
        NeighbourChoice {
            mac: "de:ad:be:ef:00:01".to_string(),
            address: "10.10.10.7".parse().unwrap(),
            interface: "enp3s0".to_string(),
            name: None,
        },
    ]
}

/// `<stem>-<suffix>.<ext>` beside `path`, for the extra images a flag
/// writes: `--screenshot-dialog` writes two extras, `--screenshot-devices`
/// three. There was a second copy of this function, `alert_path`, twenty
/// lines from the first and identical to `beside(path, "alert")` character
/// for character -- its own doc comment said so.
fn beside(path: &Path, suffix: &str) -> PathBuf {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "screenshot".to_string());
    let extension = path
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_else(|| "png".to_string());
    path.with_file_name(format!("{stem}-{suffix}.{extension}"))
}

/// `main.rs`'s debug-only `--screenshot-devices <path>` flag: the saved-
/// devices dialog, in the three states a person actually meets.
///
/// `path` is the populated one -- saved devices including a long name and
/// one that does not resolve, and a picker with something in it.
/// `<stem>-empty` is a machine with nothing saved and nothing seen on the
/// network, which is what the typed-MAC field exists for. `<stem>-typed`
/// is the real save path, driven through the real widgets: a name and a MAC
/// typed in, the real Save button pressed, and whatever the re-read book
/// then says about that device on screen.
///
/// That third image writes an address book, so it is rendered **only** when
/// `PORTHOLE_DEVICES_FILE` names one -- a development flag must not write
/// the address book of whoever is running it. Without that variable the
/// first two images are still written and the third is skipped.
pub fn run_devices(path: &Path) -> gtk::glib::ExitCode {
    let app = adw::Application::builder()
        .application_id(DEVICES_APP_ID)
        .build();
    let path = path.to_path_buf();
    let outcome = std::rc::Rc::new(std::cell::Cell::new(gtk::glib::ExitCode::FAILURE));
    let outcome_for_activate = outcome.clone();

    app.connect_activate(move |app| {
        let win = PortholeWindow::new_without_initial_load(app);
        win.open_now().set_rules(&fixture_rules());
        win.status_bar().set_status(&fixture_status());
        // The open dialog's own default width, and tall enough that this
        // dialog is what the image is about rather than the window behind
        // it -- the same reasoning `run_dialog`'s own size carries. Taller
        // than either of those, because this dialog carries two groups: at
        // the window's own 560 px default it scrolls, and an image of the
        // top third of it is not what this flag is for.
        win.set_default_size(480, 1080);
        win.present();
        pump_main_context();

        let mut all_ok = true;

        let populated = DevicesDialog::new();
        populated.set_saved(&fixture_saved_devices());
        populated.set_neighbours(&fixture_neighbours());
        populated.present(Some(&*win));
        settle();
        all_ok &= write_image(&win, &path);
        populated.dialog().close();
        settle();

        let empty = DevicesDialog::new();
        empty.set_saved(&[]);
        empty.set_neighbours(&[]);
        empty.present(Some(&*win));
        settle();
        all_ok &= write_image(&win, &beside(&path, "empty"));
        empty.dialog().close();
        settle();

        match devices_file_override() {
            Some(_) => {
                let typed = DevicesDialog::new();
                typed.reload();
                typed.present(Some(&*win));
                settle();
                // Typed by hand, not picked: the MAC of a device that is
                // switched off is not in the neighbour table to pick.
                typed.set_name_text("laptop");
                typed.set_mac_text("12:34:56:78:9a:bc");
                typed.save_button().emit_clicked();
                settle();
                all_ok &= write_image(&win, &beside(&path, "typed"));
                typed.dialog().close();
                settle();
            }
            None => eprintln!(
                "porthole-gui: --screenshot-devices: PORTHOLE_DEVICES_FILE is not set, so \
                 the save was not rendered -- this flag will not write a real address book"
            ),
        }

        if all_ok {
            outcome_for_activate.set(gtk::glib::ExitCode::SUCCESS);
        }
        app.quit();
    });

    app.run_with_args::<&str>(&[]);
    outcome.get()
}

/// The address book override, when one is set to a non-empty path. Read
/// through the same constant `porthole_core::devices` honours, rather than
/// a second copy of the variable's name written down here.
fn devices_file_override() -> Option<String> {
    std::env::var(porthole_core::devices::DEVICES_FILE_ENV)
        .ok()
        .filter(|value| !value.is_empty())
}

/// [`capture_with_dialogs`] plus the two lines every caller wrote around
/// it.
fn write_image(win: &PortholeWindow, path: &Path) -> bool {
    match capture_with_dialogs(win, path) {
        Ok(()) => {
            eprintln!("porthole-gui: wrote a screenshot to {}", path.display());
            true
        }
        Err(message) => {
            eprintln!("porthole-gui: --screenshot-devices failed: {message}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure-data coverage, independent of GTK -- these run in the crate's
    // ordinary unit-test binary, unlike `run` and `capture` themselves,
    // which need a real display and are exercised by looking at the image
    // they produce (see this milestone's own task-7 report), not by an
    // automated assertion.

    #[test]
    fn the_fixture_rules_cover_both_a_countdown_and_until_reboot() {
        // No exact count: the picture gained a third rule (the forward
        // below) and a hard length would have failed for that alone, which
        // is not what this check is about. The two `any`s already require
        // at least two rules, and they require the two that matter.
        let rules = fixture_rules();
        assert!(rules.iter().any(|r| r.expires_at != 0));
        assert!(rules.iter().any(|r| r.expires_at == 0));
    }

    #[test]
    fn one_fixture_rule_redirects_rather_than_permits() {
        // Otherwise the picture shows only rows that permit, and the whole
        // question a reader is looking at the image to answer -- whether a
        // forward reads differently from an open -- is not in it.
        let rules = fixture_rules();
        assert!(rules.iter().any(|r| !r.container_addr.is_empty()));
        assert!(rules.iter().any(|r| r.container_addr.is_empty()));
    }

    #[test]
    fn one_fixture_service_can_actually_be_forwarded() {
        // A loopback-only service a fixture Docker rule publishes on
        // loopback: the one shape that gets a Forward button, so the image
        // has one to show.
        let published_on_loopback: Vec<u16> = fixture_docker()
            .iter()
            .filter(|p| p.host_addr.is_some_and(|a| a.is_loopback()))
            .map(|p| p.host_port)
            .collect();
        assert!(fixture_services()
            .iter()
            .any(|s| matches!(s.binding, Binding::LoopbackOnly)
                && published_on_loopback.contains(&s.port)));
    }

    #[test]
    fn a_fixture_service_shares_its_port_with_a_fixture_rule() {
        // So the "already open" subtitle actually has something to render
        // against, rather than every listening row being merely actionable.
        let open_ports: Vec<u16> = fixture_rules().iter().map(|r| r.port).collect();
        assert!(fixture_services()
            .iter()
            .any(|s| open_ports.contains(&s.port)));
    }

    #[test]
    fn every_binding_variant_appears_at_least_once() {
        let services = fixture_services();
        assert!(services
            .iter()
            .any(|s| matches!(s.binding, Binding::AllInterfaces)));
        assert!(services
            .iter()
            .any(|s| matches!(s.binding, Binding::LoopbackOnly)));
        assert!(services
            .iter()
            .any(|s| matches!(s.binding, Binding::BeyondReach(_))));
    }

    #[test]
    fn the_docker_fixture_names_a_port_one_of_the_fixture_services_listens_on() {
        // Otherwise the marker has nothing to land on and the image proves
        // nothing about it.
        let ports: Vec<u16> = fixture_services().iter().map(|s| s.port).collect();
        for published in fixture_docker() {
            assert!(
                ports.contains(&published.host_port),
                "no fixture service listens on {}",
                published.host_port
            );
        }
    }

    #[test]
    fn the_device_fixture_has_one_that_does_not_resolve_and_one_long_name() {
        let devices = fixture_devices();
        assert!(devices.iter().any(|d| d.resolved.is_err()));
        assert!(
            devices.iter().any(|d| d.name.len() > 30),
            "a long device name is the case this fixture exists to show"
        );
    }

    #[test]
    fn the_saved_device_fixture_has_a_long_name_and_one_that_does_not_resolve() {
        let saved = fixture_saved_devices();
        assert!(
            saved.iter().any(|d| d.name.len() > 30),
            "a long name is where a row that cannot take one shows itself"
        );
        assert!(
            saved.iter().any(|d| d.resolved.is_err()),
            "the state a typed MAC for a switched-off device produces must be rendered"
        );
    }

    #[test]
    fn the_extra_device_images_sit_beside_the_first_one() {
        let path = Path::new("/x/devices.png");
        assert_eq!(beside(path, "empty"), PathBuf::from("/x/devices-empty.png"));
        assert_eq!(beside(path, "typed"), PathBuf::from("/x/devices-typed.png"));
    }

    #[test]
    fn the_alert_image_sits_beside_the_dialog_image() {
        assert_eq!(
            beside(Path::new("/tmp/dialog.png"), "alert"),
            PathBuf::from("/tmp/dialog-alert.png")
        );
    }

    #[test]
    fn the_fixture_status_is_an_installed_and_enforcing_firewall() {
        let status = fixture_status();
        assert!(status.firewall_available);
        assert!(status.firewall_active);
        assert!(!status.firewall_active_unknown);
    }
}
