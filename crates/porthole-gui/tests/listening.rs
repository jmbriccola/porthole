//! Runs a real `ListeningSection` inside an activated `adw::Application`,
//! the same way `tests/window.rs` and `tests/open_now.rs` do and for the
//! identical reason: `harness = false` (see `Cargo.toml`) because cargo's
//! normal test harness spawns each `#[test]` function on its own OS thread,
//! and gtk4-rs locks GTK to whichever thread makes its first call -- a
//! second GTK-touching test thread wedges the whole process. This is its
//! own `[[test]]` target, not a case added to either of those files,
//! exactly as their own comments ask a later task's implementer to do.
//!
//! Every widget property here is read back *without* pumping the main
//! loop, the same way `tests/open_now.rs`'s do: these tests assert on
//! properties this section sets directly at construction time (title,
//! subtitle, button presence), none of which need a GTK layout pass to
//! become true.
//!
//! The pure logic behind these renders -- what a title/subtitle string
//! actually says, which bindings are actionable, how rows are ordered --
//! is unit-tested directly in `src/listening_section.rs`, with no GTK
//! involved. What this file adds is proof that the real widgets carry that
//! same text and behaviour once actually built.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;

use adw::prelude::*;
use porthole_core::docker::Published;
use porthole_core::listening::{Binding, Service};
use porthole_core::model::Protocol;
use porthole_gui::listening_section::{
    ListeningSection, DOCKER_NOT_CHECKED_NOTE, DOCKER_UNAVAILABLE_NOTE,
};

/// `PortholeWindow`'s own default window width, in pixels -- the width a
/// height measurement here has to be taken at for the wrapping it sees to
/// be the wrapping a user gets.
const WINDOW_WIDTH_PX: i32 = 480;

/// Identical in shape to `tests/window.rs` and `tests/open_now.rs`'s own
/// `activate` helper: runs `f` inside a real `adw::Application` activation,
/// on the session bus `dbus-run-session` provides (see
/// `tests/container/gui-test.sh`).
fn activate<F: FnOnce(&adw::Application) + 'static>(app_id: &str, f: F) {
    let app = adw::Application::builder().application_id(app_id).build();
    let f = Rc::new(RefCell::new(Some(f)));
    app.connect_activate(move |app| {
        if let Some(f) = f.borrow_mut().take() {
            f(app);
        }
        app.quit();
    });
    app.run_with_args::<&str>(&[]);
}

/// A `Service` as `porthole_core::listening::scan` would produce one, with
/// an address consistent with `binding` -- the same fixture shape the
/// task's own brief specifies, so a reader comparing this file to the brief
/// can tell they match.
fn svc(port: u16, process: Option<&str>, binding: Binding) -> Service {
    let address = match binding {
        Binding::LoopbackOnly => IpAddr::V4(Ipv4Addr::LOCALHOST),
        Binding::AllInterfaces => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        Binding::Specific(a) => IpAddr::V4(a),
        Binding::BeyondReach(a) => IpAddr::V6(a),
    };
    Service {
        port,
        protocol: Protocol::Tcp,
        address,
        binding,
        process: process.map(str::to_string),
        pid: None,
    }
}

fn a_service_shows_its_name_and_port_the_way_the_spec_writes_it() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningTitle",
        move |_app| {
            let section = ListeningSection::new();
            section.set_services(&[svc(5173, Some("node"), Binding::AllInterfaces)]);
            *seen.borrow_mut() = Some(section.rows()[0].title().to_string());
        },
    );
    let title = result.borrow_mut().take().ok_or("activation never ran")?;
    if title != "node · 5173" {
        return Err(format!("expected \"node · 5173\", got {title:?}"));
    }
    Ok(())
}

fn a_nameless_service_shows_its_port_alone_not_a_fake_name() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningNoName",
        move |_app| {
            let section = ListeningSection::new();
            section.set_services(&[svc(4000, None, Binding::AllInterfaces)]);
            *seen.borrow_mut() = Some(section.rows()[0].title().to_string());
        },
    );
    let title = result.borrow_mut().take().ok_or("activation never ran")?;
    if title != "4000" {
        return Err(format!("expected \"4000\", got {title:?}"));
    }
    Ok(())
}

/// Opening the firewall for a loopback-only service does nothing at all.
/// Offering an Open button would let the user perform a no-op and believe
/// it worked -- and on this machine six of seven listening sockets are
/// loopback-only, so it is the most likely row to click.
fn a_loopback_only_service_is_shown_but_marked_and_cannot_be_opened() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningLoopback",
        move |_app| {
            let section = ListeningSection::new();
            section.set_services(&[svc(46715, Some("code"), Binding::LoopbackOnly)]);
            let subtitle = section.rows()[0].subtitle().map(|s| s.to_string());
            let has_open_button = section.open_button_for(0).is_some();
            *seen.borrow_mut() = Some((subtitle, has_open_button));
        },
    );
    let (subtitle, has_open_button) = result.borrow_mut().take().ok_or("activation never ran")?;
    match subtitle.as_deref() {
        Some(s) if s.contains("only on this machine") => {}
        other => {
            return Err(format!(
                "expected a subtitle mentioning \"only on this machine\", got {other:?}"
            ))
        }
    }
    if has_open_button {
        return Err(
            "there must be no Open button for a service the firewall cannot affect".to_string(),
        );
    }
    Ok(())
}

/// The opposite direction from loopback-only: this service *is* reachable
/// from the network over IPv6, and porthole simply cannot open or close a
/// rule for it. Task 1's review caught an earlier draft that folded this
/// into the loopback wording -- this section must not reintroduce that.
fn a_beyond_reach_service_gets_a_different_more_concerning_reason() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningBeyondReach",
        move |_app| {
            let section = ListeningSection::new();
            let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
            section.set_services(&[svc(22, Some("sshd"), Binding::BeyondReach(global))]);
            let subtitle = section.rows()[0].subtitle().map(|s| s.to_string());
            let has_open_button = section.open_button_for(0).is_some();
            *seen.borrow_mut() = Some((subtitle, has_open_button));
        },
    );
    let (subtitle, has_open_button) = result.borrow_mut().take().ok_or("activation never ran")?;
    let subtitle = subtitle.ok_or("a BeyondReach row must have a subtitle explaining why")?;
    if subtitle.contains("only on this machine") {
        return Err(format!(
            "a BeyondReach subtitle must not reuse LoopbackOnly's reassurance: {subtitle:?}"
        ));
    }
    if !subtitle.contains("IPv6") || !subtitle.contains("porthole doctor") {
        return Err(format!(
            "a BeyondReach subtitle must name IPv6 and point at porthole doctor: {subtitle:?}"
        ));
    }
    if has_open_button {
        return Err(
            "there must be no Open button for a service porthole cannot open over IPv4".to_string(),
        );
    }
    Ok(())
}

/// The rows a user can act on must not be buried under the ones they
/// cannot.
fn network_facing_services_come_first() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningOrder",
        move |_app| {
            let section = ListeningSection::new();
            section.set_services(&[
                svc(46715, Some("code"), Binding::LoopbackOnly),
                svc(5173, Some("node"), Binding::AllInterfaces),
            ]);
            *seen.borrow_mut() = Some(section.rows()[0].title().to_string());
        },
    );
    let title = result.borrow_mut().take().ok_or("activation never ran")?;
    if title != "node · 5173" {
        return Err(format!(
            "expected the network-facing row first, got {title:?}"
        ));
    }
    Ok(())
}

fn opening_from_a_row_pre_fills_the_port() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningActivate",
        move |_app| {
            let section = ListeningSection::new();
            section.set_services(&[svc(5173, Some("node"), Binding::AllInterfaces)]);
            *seen.borrow_mut() = Some(section.activate_open(0));
        },
    );
    let activated = result.borrow_mut().take().ok_or("activation never ran")?;
    if activated != Some(5173) {
        return Err(format!("expected Some(5173), got {activated:?}"));
    }
    Ok(())
}

/// It is in the section above, with a countdown. Offering "Open" here as
/// well invites a second attempt that the helper answers with "already
/// open" -- a refusal the user could not have anticipated from the screen.
fn a_port_already_open_is_not_offered_again() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningAlreadyOpen",
        move |_app| {
            let section = ListeningSection::new();
            section.set_open_ports(&[5173]);
            section.set_services(&[svc(5173, Some("node"), Binding::AllInterfaces)]);
            *seen.borrow_mut() = Some(section.open_button_for(0).is_some());
        },
    );
    let has_open_button = result.borrow_mut().take().ok_or("activation never ran")?;
    if has_open_button {
        return Err("a port already open must not be offered again".to_string());
    }
    Ok(())
}

/// I6: a helper round trip that fails must withdraw an "already open" claim
/// it can no longer confirm, not leave it standing on whatever
/// `set_open_ports` last said -- `set_open_ports_unknown` is the method a
/// caller reaches for that.
fn a_helper_failure_withdraws_a_stale_already_open_claim() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningOpenPortsUnknown",
        move |_app| {
            let section = ListeningSection::new();
            section.set_open_ports(&[5173]);
            section.set_services(&[svc(5173, Some("node"), Binding::AllInterfaces)]);
            let had_button_before = section.open_button_for(0).is_some();
            let subtitle_before = section
                .rows()
                .first()
                .and_then(|r| r.subtitle())
                .map(|s| s.to_string());

            section.set_open_ports_unknown();

            let has_button_after = section.open_button_for(0).is_some();
            let subtitle_after = section
                .rows()
                .first()
                .and_then(|r| r.subtitle())
                .map(|s| s.to_string());
            *seen.borrow_mut() = Some((
                had_button_before,
                subtitle_before,
                has_button_after,
                subtitle_after,
            ));
        },
    );
    let (had_button_before, subtitle_before, has_button_after, subtitle_after) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if had_button_before {
        return Err(
            "fixture setup: expected the port to read as already open before the failure"
                .to_string(),
        );
    }
    match subtitle_before.as_deref() {
        Some(s) if s.contains("already open") => {}
        other => {
            return Err(format!(
                "fixture setup: expected \"already open\" in the subtitle before the \
                 failure, got {other:?}"
            ))
        }
    }
    if !has_button_after {
        return Err(
            "set_open_ports_unknown must stop withholding the Open button on a claim \
             porthole can no longer confirm"
                .to_string(),
        );
    }
    if subtitle_after
        .as_deref()
        .is_some_and(|s| s.contains("already open"))
    {
        return Err(format!(
            "set_open_ports_unknown must stop the stale \"already open\" claim: {subtitle_after:?}"
        ));
    }
    Ok(())
}

/// The control half of the disambiguation check below: `LoopbackOnly`'s
/// subtitle is a fixed safety fact, not an address report, so two
/// `LoopbackOnly` rows on the same port -- a genuine `127.0.0.1` +
/// `::1` dual-stack pair -- correctly render the *same* text. There is no
/// button to click twice here either way, so unlike the network-facing
/// case this is not the readability problem the milestone's final wave
/// tracks; this test only pins that the fixed wording really is fixed.
fn loopback_only_rows_share_the_same_reassurance_regardless_of_address() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningDualStack",
        move |_app| {
            let section = ListeningSection::new();
            section.set_services(&[svc(53, Some("systemd-resolve"), Binding::LoopbackOnly), {
                let mut s = svc(53, Some("systemd-resolve"), Binding::LoopbackOnly);
                s.address = IpAddr::V6(Ipv6Addr::LOCALHOST);
                s
            }]);
            let rows = section.rows();
            let subtitle_a = rows[0].subtitle().map(|s| s.to_string());
            let subtitle_b = rows
                .get(1)
                .and_then(|r| r.subtitle())
                .map(|s| s.to_string());
            *seen.borrow_mut() = Some((subtitle_a, subtitle_b));
        },
    );
    let (subtitle_a, subtitle_b) = result.borrow_mut().take().ok_or("activation never ran")?;
    // Both are LoopbackOnly, so both render the same fixed reassurance --
    // that binding's subtitle deliberately does not vary by address (the
    // safety fact is identical either way). This is the control half of
    // the disambiguation check: proof the two rows really did both render,
    // not proof of disambiguation itself.
    if subtitle_a != subtitle_b {
        return Err(format!(
            "two LoopbackOnly rows should share the same reassurance text: {subtitle_a:?} vs {subtitle_b:?}"
        ));
    }
    Ok(())
}

/// Same idea, but for the case that actually needs disambiguating: two
/// network-facing rows on the same port. Their subtitles must differ,
/// because they are shown as the literal bind address.
fn dual_stack_network_facing_rows_show_different_addresses() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningDualStackFacing",
        move |_app| {
            let section = ListeningSection::new();
            let v4 = svc(5355, Some("systemd-resolve"), Binding::AllInterfaces);
            let mut v6 = svc(5355, Some("systemd-resolve"), Binding::AllInterfaces);
            v6.address = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
            section.set_services(&[v4, v6]);
            let rows = section.rows();
            let subtitle_a = rows[0].subtitle().map(|s| s.to_string());
            let subtitle_b = rows
                .get(1)
                .and_then(|r| r.subtitle())
                .map(|s| s.to_string());
            *seen.borrow_mut() = Some((subtitle_a, subtitle_b));
        },
    );
    let (subtitle_a, subtitle_b) = result.borrow_mut().take().ok_or("activation never ran")?;
    if subtitle_a == subtitle_b {
        return Err(format!(
            "two same-port network-facing rows must not read as identical: both {subtitle_a:?}"
        ));
    }
    Ok(())
}

/// A calm empty state, not an error -- mirrors `OpenNowSection`'s own
/// `an_empty_list_is_a_calm_note_not_an_error`, checked the same way: the
/// CSS classes and the absence of the scan-failure state, not the words
/// alone. A text-only check would still pass if the calm note grew
/// `.css_classes(["error"])`.
fn nothing_listening_is_a_calm_note_not_an_error() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningEmpty",
        move |_app| {
            let section = ListeningSection::new();
            section.set_services(&[]);
            let note = section.empty_note();
            let text = note.as_ref().map(|n| n.label().to_string());
            let css_classes: Vec<String> = note
                .as_ref()
                .map(|n| n.css_classes().iter().map(|c| c.to_string()).collect())
                .unwrap_or_default();
            let error_showing = section.error_note().is_some();
            let rows_empty = section.rows().is_empty();
            *seen.borrow_mut() = Some((text, css_classes, error_showing, rows_empty));
        },
    );
    let (text, css_classes, error_showing, rows_empty) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    let text = text.ok_or("a confirmed-empty scan must show its own note")?;
    if !text.starts_with("Nothing else is listening") {
        return Err(format!(
            "expected the confirmed-empty note to say so, got {text:?}"
        ));
    }
    if css_classes.iter().any(|c| c == "error" || c == "warning") {
        return Err(format!(
            "the empty state carries an error/warning CSS class: {css_classes:?}"
        ));
    }
    if error_showing {
        return Err(
            "the \"could not check\" state must not be on screen alongside a confirmed-empty \
             scan"
                .to_string(),
        );
    }
    if !rows_empty {
        return Err("rows must be empty when nothing is listening".to_string());
    }
    Ok(())
}

/// I5: before `set_services` has ever been called, this section must not
/// be sitting on the calm "Nothing else is listening" claim -- a fresh
/// `ListeningSection` has not scanned anything yet to earn that.
fn the_initial_state_before_any_scan_is_neither_calm_nor_populated() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningLoading",
        move |_app| {
            let section = ListeningSection::new();
            *seen.borrow_mut() = Some((
                section.loading_note().is_some(),
                section.empty_note().is_some(),
                section.error_note().is_some(),
                section.rows().is_empty(),
            ));
        },
    );
    let (loading, calm, error, rows_empty) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if !loading {
        return Err("a freshly constructed section must show its loading state".to_string());
    }
    if calm {
        return Err(
            "\"Nothing else is listening\" must not be the default before any scan has run"
                .to_string(),
        );
    }
    if error {
        return Err("there is no scan failure to report yet either".to_string());
    }
    if !rows_empty {
        return Err("there must be no rows before a scan has ever run".to_string());
    }
    Ok(())
}

/// I4: a `/proc` scan that fails outright must not leave the calm
/// "Nothing else is listening" page up -- a stderr line is not a UI, and
/// from the user's side "porthole could not check" and "porthole checked
/// and found nothing" are exactly the collapse this project keeps finding.
/// Checked structurally (icon, CSS class), the same way
/// `nothing_listening_is_a_calm_note_not_an_error` above checks the
/// calm state's own icon.
fn a_scan_failure_does_not_render_as_the_calm_empty_state() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningScanFailed",
        move |_app| {
            let section = ListeningSection::new();
            // A prior successful scan, so this also proves the failure
            // state actually *displaces* real data rather than merely
            // never having shown any.
            section.set_services(&[svc(5173, Some("node"), Binding::AllInterfaces)]);
            section.set_scan_failed("could not check what is listening: permission denied");
            let calm = section.empty_note();
            let error = section.error_note();
            let icon_name = error
                .as_ref()
                .and_then(|p| p.icon_name())
                .map(|s| s.to_string());
            let css_classes: Vec<String> = error
                .as_ref()
                .map(|p| p.css_classes().iter().map(|c| c.to_string()).collect())
                .unwrap_or_default();
            let description = error
                .as_ref()
                .and_then(|p| p.description())
                .map(|s| s.to_string());
            let rows_empty = section.rows().is_empty();
            *seen.borrow_mut() = Some((
                calm.is_some(),
                error.is_some(),
                icon_name,
                css_classes,
                description,
                rows_empty,
            ));
        },
    );
    let (calm_showing, error_showing, icon_name, css_classes, description, rows_empty) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if calm_showing {
        return Err(
            "the calm \"Nothing else is listening\" page must not survive a scan \
                     failure that came after it"
                .to_string(),
        );
    }
    if !error_showing {
        return Err("a scan failure must render its own, distinguishable state".to_string());
    }
    let icon = icon_name.unwrap_or_default();
    if !(icon.contains("error") || icon.contains("warning")) {
        return Err(format!(
            "the scan-failed state's icon must read as trouble: {icon:?}"
        ));
    }
    if !css_classes.iter().any(|c| c == "error" || c == "warning") {
        return Err(format!(
            "the scan-failed state must carry an error/warning CSS class: {css_classes:?}"
        ));
    }
    match description.as_deref() {
        Some(d) if d.contains("permission denied") => {}
        other => {
            return Err(format!(
                "the scan's own reason must be shown, verbatim: {other:?}"
            ))
        }
    }
    if !rows_empty {
        return Err("the stale row from before the failure must not still be showing".to_string());
    }
    Ok(())
}

/// Fix round 2, item 1: the actual bug. `refresh` (`window.rs`) runs the
/// `/proc` scan and the helper's `list`/`status` round trip as two
/// independent futures, and a scan failure calling `set_scan_failed`
/// followed by a *successful* helper fetch calling `set_open_ports` is the
/// *likely* arrival order in practice (a `/proc` read on the thread pool
/// reliably beats a system-bus connect plus two polkit-checked calls), not
/// an edge case. `set_open_ports` alone must not be able to rebuild the
/// calm "Nothing else is listening" page out from under a scan failure --
/// before this fix it did, because `apply` decided from `services.is_empty()`,
/// which `set_scan_failed` itself made true.
fn a_scan_failure_survives_a_later_set_open_ports() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningScanFailedThenPorts",
        move |_app| {
            let section = ListeningSection::new();
            section.set_scan_failed("could not check what is listening: permission denied");
            section.set_open_ports(&[5173]);
            *seen.borrow_mut() = Some((
                section.empty_note().is_some(),
                section.error_note().is_some(),
            ));
        },
    );
    let (calm_showing, error_showing) = result.borrow_mut().take().ok_or("activation never ran")?;
    if calm_showing {
        return Err(
            "a set_open_ports arriving after a scan failure must not resurrect the calm \
             \"Nothing else is listening\" page"
                .to_string(),
        );
    }
    if !error_showing {
        return Err(
            "the scan-failed state must survive a set_open_ports that arrives after it".to_string(),
        );
    }
    Ok(())
}

/// The other half of the same hole (I5, the loading state): with no scan
/// having run at all yet, a `set_open_ports` arriving first (the helper
/// answering before `/proc` has been read) must not manufacture the calm
/// page either -- the loading state exists precisely to keep this section
/// from asserting "nothing is listening" before it has asked.
fn the_loading_state_survives_a_set_open_ports_before_any_scan() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningPortsBeforeScan",
        move |_app| {
            let section = ListeningSection::new();
            section.set_open_ports(&[5173]);
            *seen.borrow_mut() = Some((
                section.loading_note().is_some(),
                section.empty_note().is_some(),
            ));
        },
    );
    let (loading_showing, calm_showing) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if calm_showing {
        return Err(
            "a set_open_ports arriving before any scan must not produce the calm \"Nothing \
             else is listening\" page"
                .to_string(),
        );
    }
    if !loading_showing {
        return Err(
            "the loading state must survive a set_open_ports that arrives before any \
                     scan"
                .to_string(),
        );
    }
    Ok(())
}

fn published(port: u16, host_addr: Option<&str>) -> Published {
    Published {
        host_addr: host_addr.map(|a| a.parse().unwrap()),
        host_port: port,
        protocol: Protocol::Tcp,
        container_addr: "172.17.0.2".parse().unwrap(),
        container_port: 80,
    }
}

/// The marker and the address, on the one row Docker's own list names --
/// and on no other row, and no group-level caveat once the list has
/// actually arrived.
fn a_docker_published_row_carries_its_marker_and_address() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningDocker",
        move |_app| {
            let section = ListeningSection::new();
            section.set_services(&[
                svc(8080, Some("docker-proxy"), Binding::AllInterfaces),
                svc(4000, Some("node"), Binding::AllInterfaces),
            ]);
            section.set_docker_ports(&[published(8080, None)]);
            let rows = section.rows();
            let index = rows
                .iter()
                .position(|r| r.title().contains("8080"))
                .expect("the 8080 row must exist");
            let other = 1 - index;
            *seen.borrow_mut() = Some((
                rows[index].subtitle().map(|s| s.to_string()),
                section.is_marked_docker(index),
                section.is_marked_docker(other),
                section.group_description(),
            ));
        },
    );
    let (subtitle, marked, other_marked, description) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    let subtitle = subtitle.ok_or("the row must have a subtitle")?;
    if !subtitle.contains("docker: published on every interface") {
        return Err(format!("expected the published address, got: {subtitle}"));
    }
    if !marked {
        return Err("a published row must carry the marker".to_string());
    }
    if other_marked {
        return Err("a row Docker does not publish must carry no marker".to_string());
    }
    if description.is_some() {
        return Err(format!(
            "a checked list needs no caveat, got: {description:?}"
        ));
    }
    Ok(())
}

fn a_row_published_on_one_address_names_that_address() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningDockerLoopback",
        move |_app| {
            let section = ListeningSection::new();
            section.set_services(&[svc(5432, Some("docker-proxy"), Binding::LoopbackOnly)]);
            section.set_docker_ports(&[published(5432, Some("127.0.0.1"))]);
            *seen.borrow_mut() = Some(section.rows()[0].subtitle().map(|s| s.to_string()));
        },
    );
    let subtitle = result
        .borrow_mut()
        .take()
        .ok_or("activation never ran")?
        .ok_or("the row must have a subtitle")?;
    if !subtitle.contains("docker: published on 127.0.0.1") {
        return Err(format!("expected the published address, got: {subtitle}"));
    }
    Ok(())
}

/// A host port can carry more than one DNAT rule, and this row is where a
/// user reads what Docker did with it. The lookup behind it used to return
/// the first match only, so a second address was invisible on a row that
/// read as the whole picture.
fn a_row_with_two_docker_rules_names_both_addresses() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningDockerTwoRules",
        move |_app| {
            let section = ListeningSection::new();
            section.set_services(&[svc(5432, Some("docker-proxy"), Binding::AllInterfaces)]);
            section.set_docker_ports(&[
                published(5432, Some("127.0.0.1")),
                published(5432, Some("10.0.0.5")),
            ]);
            *seen.borrow_mut() = Some((
                section.rows()[0].subtitle().map(|s| s.to_string()),
                section.is_marked_docker(0),
            ));
        },
    );
    let (subtitle, marked) = result.borrow_mut().take().ok_or("activation never ran")?;
    let subtitle = subtitle.ok_or("the row must have a subtitle")?;
    for address in ["127.0.0.1", "10.0.0.5"] {
        if !subtitle.contains(address) {
            return Err(format!("{address} is missing from the row: {subtitle}"));
        }
    }
    if !marked {
        return Err("a row with two published rules must still carry the marker".to_string());
    }
    Ok(())
}

/// All three things an unmarked row can mean, in the order a real session
/// meets them: rows on screen with no Docker answer yet, then an answer,
/// then an answer lost.
fn the_group_note_tracks_all_three_docker_states() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningDockerStates",
        move |_app| {
            let section = ListeningSection::new();
            section.set_services(&[svc(8080, Some("node"), Binding::AllInterfaces)]);
            let not_checked = (section.group_description(), section.is_marked_docker(0));

            section.set_docker_ports(&[published(8080, None)]);
            let checked = (section.group_description(), section.is_marked_docker(0));

            section.set_docker_unavailable();
            let unavailable = (section.group_description(), section.is_marked_docker(0));

            *seen.borrow_mut() = Some((not_checked, checked, unavailable));
        },
    );
    let (not_checked, checked, unavailable) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    // The state a real launch is in for as long as the helper takes: the
    // `/proc` scan has landed and `docker_ports` has not. Nothing has
    // failed, so nothing may say it has.
    if not_checked.0.as_deref() != Some(DOCKER_NOT_CHECKED_NOTE) || not_checked.1 {
        return Err(format!(
            "rows with no Docker answer yet must say so, and carry no marker: {not_checked:?}"
        ));
    }
    if checked.0.is_some() || !checked.1 {
        return Err(format!(
            "a checked list must mark and not caveat: {checked:?}"
        ));
    }
    if unavailable.0.as_deref() != Some(DOCKER_UNAVAILABLE_NOTE) || unavailable.1 {
        return Err(format!(
            "losing the list must drop the marker and report the failure: {unavailable:?}"
        ));
    }
    Ok(())
}

/// The defect this state exists for, stated as its own check: the notice a
/// user reads while the helper is still answering must not be the one that
/// says the helper failed.
fn a_section_waiting_on_the_helper_does_not_report_a_failure() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningDockerPending",
        move |_app| {
            let section = ListeningSection::new();
            // Exactly the order a launch produces: the `/proc` scan and the
            // helper's `list` both land before `docker_ports` does.
            section.set_services(&[svc(8080, Some("node"), Binding::AllInterfaces)]);
            section.set_open_ports(&[]);
            *seen.borrow_mut() = Some(section.group_description());
        },
    );
    let description = result.borrow_mut().take().ok_or("activation never ran")?;
    if description.as_deref() == Some(DOCKER_UNAVAILABLE_NOTE) {
        return Err(
            "a section still waiting on docker_ports must not claim the helper failed".to_string(),
        );
    }
    if description.as_deref() != Some(DOCKER_NOT_CHECKED_NOTE) {
        return Err(format!(
            "expected the not-checked note, got {description:?}"
        ));
    }
    Ok(())
}

/// The same measurement `tests/open_now.rs` makes on its own section, on
/// this one: a quiet state is one section among several, not a view of its
/// own. Both sections draw their quiet states from the same function
/// (`quiet.rs`), and a window has both, so a regression in either one is
/// what puts the other below the fold.
fn the_confirmed_empty_state_is_no_taller_than_one_rendered_service() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.ListeningEmptyHeight",
        move |_app| {
            let section = ListeningSection::new();
            section.set_services(&[]);
            let (_, empty, _, _) = section
                .widget()
                .measure(gtk::Orientation::Vertical, WINDOW_WIDTH_PX);
            section.set_services(&[svc(5173, Some("node"), Binding::AllInterfaces)]);
            let (_, one_service, _, _) = section
                .widget()
                .measure(gtk::Orientation::Vertical, WINDOW_WIDTH_PX);
            let expands = section.widget().compute_expand(gtk::Orientation::Vertical);
            *seen.borrow_mut() = Some((empty, one_service, expands));
        },
    );
    let (empty, one_service, expands) = result.borrow_mut().take().ok_or("activation never ran")?;
    if empty > one_service {
        return Err(format!(
            "the empty state wants {empty}px of height, more than the {one_service}px this \
             section takes with a service actually in it"
        ));
    }
    if expands {
        return Err(
            "the empty state claims vertical expansion, which is what pushes every other \
             section down the window"
                .to_string(),
        );
    }
    Ok(())
}

/// One named check, run by `main` below -- see `tests/window.rs`'s own
/// `Case` alias for why this is a type alias rather than spelled out
/// inline.
type Case = (&'static str, fn() -> Result<(), String>);

fn main() {
    let cases: [Case; 21] = [
        (
            "a_service_shows_its_name_and_port_the_way_the_spec_writes_it",
            a_service_shows_its_name_and_port_the_way_the_spec_writes_it,
        ),
        (
            "a_nameless_service_shows_its_port_alone_not_a_fake_name",
            a_nameless_service_shows_its_port_alone_not_a_fake_name,
        ),
        (
            "a_loopback_only_service_is_shown_but_marked_and_cannot_be_opened",
            a_loopback_only_service_is_shown_but_marked_and_cannot_be_opened,
        ),
        (
            "a_beyond_reach_service_gets_a_different_more_concerning_reason",
            a_beyond_reach_service_gets_a_different_more_concerning_reason,
        ),
        (
            "network_facing_services_come_first",
            network_facing_services_come_first,
        ),
        (
            "opening_from_a_row_pre_fills_the_port",
            opening_from_a_row_pre_fills_the_port,
        ),
        (
            "a_port_already_open_is_not_offered_again",
            a_port_already_open_is_not_offered_again,
        ),
        (
            "a_helper_failure_withdraws_a_stale_already_open_claim",
            a_helper_failure_withdraws_a_stale_already_open_claim,
        ),
        (
            "loopback_only_rows_share_the_same_reassurance_regardless_of_address",
            loopback_only_rows_share_the_same_reassurance_regardless_of_address,
        ),
        (
            "dual_stack_network_facing_rows_show_different_addresses",
            dual_stack_network_facing_rows_show_different_addresses,
        ),
        (
            "nothing_listening_is_a_calm_note_not_an_error",
            nothing_listening_is_a_calm_note_not_an_error,
        ),
        (
            "the_confirmed_empty_state_is_no_taller_than_one_rendered_service",
            the_confirmed_empty_state_is_no_taller_than_one_rendered_service,
        ),
        (
            "the_initial_state_before_any_scan_is_neither_calm_nor_populated",
            the_initial_state_before_any_scan_is_neither_calm_nor_populated,
        ),
        (
            "a_scan_failure_does_not_render_as_the_calm_empty_state",
            a_scan_failure_does_not_render_as_the_calm_empty_state,
        ),
        (
            "a_scan_failure_survives_a_later_set_open_ports",
            a_scan_failure_survives_a_later_set_open_ports,
        ),
        (
            "the_loading_state_survives_a_set_open_ports_before_any_scan",
            the_loading_state_survives_a_set_open_ports_before_any_scan,
        ),
        (
            "a_docker_published_row_carries_its_marker_and_address",
            a_docker_published_row_carries_its_marker_and_address,
        ),
        (
            "a_row_published_on_one_address_names_that_address",
            a_row_published_on_one_address_names_that_address,
        ),
        (
            "a_row_with_two_docker_rules_names_both_addresses",
            a_row_with_two_docker_rules_names_both_addresses,
        ),
        (
            "the_group_note_tracks_all_three_docker_states",
            the_group_note_tracks_all_three_docker_states,
        ),
        (
            "a_section_waiting_on_the_helper_does_not_report_a_failure",
            a_section_waiting_on_the_helper_does_not_report_a_failure,
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
