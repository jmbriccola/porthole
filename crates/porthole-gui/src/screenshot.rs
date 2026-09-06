//! `main.rs`'s debug-only `--screenshot <path>` flag: populates a real
//! [`PortholeWindow`] with invented data, renders exactly what GTK is
//! currently displaying, saves that to `path` as a PNG, and exits.
//!
//! **Fixture data, never live data.** [`run`] never lets a live helper round
//! trip or a `/proc` scan touch the window at all --
//! [`PortholeWindow::new_without_initial_load`] is what makes that true,
//! rather than [`PortholeWindow::new`] plus a hope that the fixture setters
//! below win whatever race they would otherwise be in against the real
//! ones. Either real source would be the wrong picture for this flag's own
//! purpose: the container this runs in has no `porthole-helper` and nothing
//! open, so a live read would screenshot an empty window, and `/proc` in
//! that same container reflects whatever this milestone's own test process
//! happens to have listening, not a machine anyone chose to show.
//!
//! The fixture below is invented, not measured -- unlike
//! `.superpowers/sdd/milestone-4-verified-facts.md`, which this module does
//! not draw on. It reuses the port numbers and addresses this project's own
//! README and `docs/json-schema.md` already use as examples (`5173/tcp`,
//! `10.10.10.0/24`, `firewalld 2.4.4`), so the screenshot reads as the same
//! running example the rest of the documentation already shows, not a new
//! one invented just for this image.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use adw::prelude::*;

use porthole_core::clock::{Clock, SystemClock};
use porthole_core::ipc::{WireRule, WireStatus};
use porthole_core::listening::{Binding, Service};
use porthole_core::model::Protocol;

use crate::window::PortholeWindow;

/// A session-bus application id distinct from the real one (`crate::app::APP_ID`)
/// and from every id `tests/window.rs` claims for itself, so a `--screenshot`
/// run sharing a session bus with anything else this milestone starts never
/// collides with it.
const APP_ID: &str = "com.jacopobriccola.Porthole.Screenshot";

/// Two open rules: one mid-countdown towards the current subnet, one
/// towards "anyone" and until reboot -- between them, both scope words
/// `open_now.rs` renders and both of the two ways it renders a remaining
/// duration.
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
        },
    ]
}

/// Five listening services, one of each thing `listening_section.rs` can
/// render: a network-facing one already open above (so its own "already
/// open" wording shows, not a second Open button for a port `fixture_rules`
/// already opened); a network-facing one still actionable; one reachable
/// only over IPv6 (`Binding::BeyondReach`, the warning icon); and two
/// loopback-only ones, one with a resolved process name and one without, the
/// same distinction `porthole listen`'s own module doc measures as the
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
            port: 22,
            protocol: Protocol::Tcp,
            address: IpAddr::V6(beyond_reach_addr),
            binding: Binding::BeyondReach(beyond_reach_addr),
            process: Some("sshd".to_string()),
            pid: Some(842),
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
        // but `WireStatus::detail` (added for `porthole-core`'s own
        // `BackendHealth::detail`, item 5 of the milestone's task 6 review)
        // has no default and this call site has to set something.
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
    // is the `adw::ToolbarView` `PortholeWindow::new`'s own construction
    // gives the window as a whole.
    let content = AdwApplicationWindowExt::content(&**win)
        .ok_or_else(|| "the window has no content widget to render".to_string())?;
    let parent = content
        .parent()
        .ok_or_else(|| "the content widget has no parent to render it from".to_string())?;

    let snapshot = gtk::Snapshot::new();
    parent.snapshot_child(&content, &snapshot);
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
        win.status_bar().set_status(&fixture_status());

        // Taller than `PortholeWindow::build`'s own 480x560 default: this
        // flag's own fixture data -- two "Open now" rows plus five
        // "Listening" ones, deliberately one of every state those sections
        // can render -- does not fit the ordinary default without the
        // `gtk::ScrolledWindow` around them scrolling, which would leave the
        // screenshot cutting the last row off mid-way rather than showing
        // what this flag exists to show. `set_default_size` before the
        // first `present()`, never after -- see `window.rs`'s own module
        // doc on why a breakpoint (and, the same way, an allocation) only
        // ever reflects a size set before that first `present()`.
        win.set_default_size(480, 660);
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

#[cfg(test)]
mod tests {
    use super::*;

    // Pure-data coverage, independent of GTK -- these run in the crate's
    // ordinary unit-test binary, unlike `run` and `capture` themselves,
    // which need a real display and are exercised by looking at the image
    // they produce (see this milestone's own task-7 report), not by an
    // automated assertion.

    #[test]
    fn one_fixture_rule_counts_down_and_the_other_is_until_reboot() {
        let rules = fixture_rules();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().any(|r| r.expires_at != 0));
        assert!(rules.iter().any(|r| r.expires_at == 0));
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
    fn the_fixture_status_is_an_installed_and_enforcing_firewall() {
        let status = fixture_status();
        assert!(status.firewall_available);
        assert!(status.firewall_active);
        assert!(!status.firewall_active_unknown);
    }
}
