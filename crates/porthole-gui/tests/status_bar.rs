//! Runs a real `StatusBar` inside an activated `adw::Application`, the same
//! way `tests/window.rs`, `tests/open_now.rs`, `tests/listening.rs` and
//! `tests/open_dialog.rs` do and for the identical reason: `harness = false`
//! (see `Cargo.toml`) because cargo's normal test harness spawns each
//! `#[test]` function on its own OS thread, and gtk4-rs locks GTK to
//! whichever thread makes its first call -- a second GTK-touching test
//! thread wedges the whole process. This is its own `[[test]]` target, not
//! a case added to any of those files, exactly as each of their own
//! comments asks a later task's implementer to do.
//!
//! Every widget property here is read back the same way the other files'
//! are -- without pumping the main loop, since everything asserted (the
//! label's own text, the banner's own title and `revealed` state) is set
//! directly by `status_bar.rs`'s own code, not something a GTK layout pass
//! would need to compute first.
//!
//! `StatusBar::set_status`'s pure logic -- the three-way enforcing/not-
//! running/unknown word, the no-firewall and unreachable titles never
//! saying the same thing -- is unit-tested directly in `src/status_bar.rs`,
//! with no GTK involved. What this file adds is proof that the real
//! widgets carry that same text once actually built.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use porthole_core::backend::NO_FIREWALL_MESSAGE;
use porthole_core::ipc::WireStatus;
use porthole_gui::status_bar::StatusBar;

/// Identical in shape to the other test files' own `activate` helper: runs
/// `f` inside a real `adw::Application` activation, on the session bus
/// `dbus-run-session` provides (see `tests/container/gui-test.sh`).
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

/// A `WireStatus` fixture. `backend_and_version` is `None` for "no firewall
/// at all" (`firewall_available: false`, `detail` set to
/// `porthole_core::backend::NO_FIREWALL_MESSAGE` -- imported, not retyped:
/// an earlier version of this fixture retyped a shortened, 136-character
/// prefix of that 248-character string, so nothing here ever rendered what
/// `StatusBar` actually shows for this case); `Some((name, version))` for
/// an installed backend, `active` deciding whether it is reported as
/// enforcing anything.
fn status(backend_and_version: Option<(&str, &str)>, active: bool) -> WireStatus {
    let (backend, version, available, detail) = match backend_and_version {
        Some((backend, version)) => (
            backend.to_string(),
            version.to_string(),
            true,
            String::new(),
        ),
        None => (
            String::new(),
            String::new(),
            false,
            NO_FIREWALL_MESSAGE.to_string(),
        ),
    };
    WireStatus {
        backend,
        firewall_available: available,
        firewall_active: active,
        firewall_active_unknown: false,
        firewall_version: version,
        detail,
        location: String::new(),
        interface: String::new(),
        address: String::new(),
        cidr: String::new(),
        rules: Vec::new(),
    }
}

fn the_status_line_names_the_backend_and_whether_it_is_enforcing() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusEnforcing",
        move |_app| {
            let bar = StatusBar::new();
            bar.set_status(&status(Some(("firewalld", "2.4.4")), true));
            *seen.borrow_mut() = Some((bar.text(), bar.is_prominent()));
        },
    );
    let (text, prominent) = result.borrow_mut().take().ok_or("activation never ran")?;
    if !text.contains("firewalld") {
        return Err(format!("expected the backend's name in {text:?}"));
    }
    if !text.contains("2.4.4") {
        return Err(format!("expected the backend's version in {text:?}"));
    }
    if prominent {
        return Err("an installed, enforcing firewall must not be prominent".to_string());
    }
    Ok(())
}

/// With no firewall, every port is already reachable, and a grey line at
/// the bottom of the window is not where that belongs: the user would read
/// the rest of the app as if it were protecting them. Prominence itself is
/// what this checks -- the banner is revealed, with a real, non-empty
/// title. What that title actually says (and, separately, where the full
/// "already reachable" explanation lives) is
/// `the_no_firewall_case_shows_a_short_banner_and_the_full_detail_on_the_line`'s
/// job, below.
fn no_firewall_at_all_is_prominent_not_a_footnote() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusNoFirewall",
        move |_app| {
            let bar = StatusBar::new();
            bar.set_status(&status(None, false));
            *seen.borrow_mut() =
                Some((bar.is_prominent(), bar.banner_widget().title().to_string()));
        },
    );
    let (prominent, banner_title) = result.borrow_mut().take().ok_or("activation never ran")?;
    if !prominent {
        return Err(
            "no firewall at all must not be rendered as an ordinary status line".to_string(),
        );
    }
    if banner_title.is_empty() {
        return Err("the banner must show a real title, not an empty one".to_string());
    }
    Ok(())
}

/// An earlier version of this case put `WireStatus::detail` -- three
/// sentences, written for a CLI's own
/// per-command error ("**this port** is already reachable… Setting up a
/// firewall is outside what porthole does") -- directly into the banner's
/// one-line `title`. This checks the real widgets carry the corrected
/// split: a short, banner-appropriate title (nothing from `detail`'s own
/// CLI-register tail), and the full `detail`, verbatim, on `line`
/// underneath -- checked by exact equality against
/// `porthole_core::backend::NO_FIREWALL_MESSAGE`, the real constant
/// `backend::detect` actually fails with, not a fixture's own
/// paraphrase of it.
fn the_no_firewall_case_shows_a_short_banner_and_the_full_detail_on_the_line() -> Result<(), String>
{
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusNoFirewallDetail",
        move |_app| {
            let bar = StatusBar::new();
            bar.set_status(&status(None, false));
            *seen.borrow_mut() = Some((
                bar.banner_widget().title().to_string(),
                bar.line_widget().label().to_string(),
            ));
        },
    );
    let (banner_title, line_text) = result.borrow_mut().take().ok_or("activation never ran")?;
    if banner_title.len() >= NO_FIREWALL_MESSAGE.len() {
        return Err(format!(
            "the banner title must be short, authored for this surface -- not the helper's own \
             {}-character explanation: {banner_title:?}",
            NO_FIREWALL_MESSAGE.len()
        ));
    }
    if banner_title.to_lowercase().contains("reachable") {
        return Err(format!(
            "the banner title must not itself claim reachability: {banner_title:?}"
        ));
    }
    if line_text != NO_FIREWALL_MESSAGE {
        return Err(format!(
            "expected the wire's own detail verbatim on the line ({NO_FIREWALL_MESSAGE:?}), got \
             {line_text:?}"
        ));
    }
    Ok(())
}

fn an_installed_but_stopped_firewall_says_stopped_not_missing() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusStopped",
        move |_app| {
            let bar = StatusBar::new();
            bar.set_status(&status(Some(("firewalld", "2.4.4")), false));
            *seen.borrow_mut() = Some((bar.text(), bar.is_prominent()));
        },
    );
    let (text, prominent) = result.borrow_mut().take().ok_or("activation never ran")?;
    if !text.contains("not running") {
        return Err(format!("expected \"not running\" in {text:?}"));
    }
    if text.contains("no firewall") {
        return Err(format!(
            "an installed, stopped firewall must not read as \"no firewall\": {text:?}"
        ));
    }
    // The control half: an installed-but-stopped firewall is a fact worth
    // reading, but it is not the "everything is already reachable" case --
    // see `no_firewall_at_all_is_prominent_not_a_footnote` above for the
    // one that is.
    if prominent {
        return Err("an installed, stopped firewall must not be prominent".to_string());
    }
    Ok(())
}

/// The distinction this module exists to keep apart: "no firewall" is a
/// confirmed fact (this port genuinely is already reachable); "the helper
/// could not be reached" is an absence of information (porthole simply does
/// not know). Both are prominent -- neither is a footnote -- but only the
/// first may claim reachability.
fn an_unreachable_helper_is_prominent_but_does_not_claim_reachability() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusUnreachable",
        move |_app| {
            let bar = StatusBar::new();
            bar.set_unreachable("could not reach the porthole helper: timed out");
            *seen.borrow_mut() = Some((bar.text(), bar.is_prominent()));
        },
    );
    let (text, prominent) = result.borrow_mut().take().ok_or("activation never ran")?;
    if !prominent {
        return Err(
            "an unreachable helper must not be rendered as an ordinary status line".to_string(),
        );
    }
    if text.contains("already reachable") {
        return Err(format!(
            "an unreachable helper must not claim reachability either way: {text:?}"
        ));
    }
    if !text.to_lowercase().contains("helper") {
        return Err(format!("expected the text to name the helper: {text:?}"));
    }
    Ok(())
}

/// Three states, not two, mirroring `porthole-cli`'s own
/// `firewall_active_unknown` distinction: a firewall porthole could not
/// confirm the activity of must not read the same as one it confirmed is
/// stopped.
fn a_firewall_porthole_could_not_read_is_not_confused_with_a_confirmed_stop() -> Result<(), String>
{
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusUnknown",
        move |_app| {
            let bar = StatusBar::new();
            let mut unknown = status(Some(("ufw", "0.36.2")), false);
            unknown.firewall_active_unknown = true;
            bar.set_status(&unknown);
            *seen.borrow_mut() = Some(bar.text());
        },
    );
    let text = result.borrow_mut().take().ok_or("activation never ran")?;
    if text.contains("not running") {
        return Err(format!(
            "a firewall porthole could not read must not claim it confirmed a stop: {text:?}"
        ));
    }
    // The positive half: not merely "not the confirmed-stopped wording",
    // which an `"enforcing"` claim -- the dangerous direction -- would also
    // pass. Pin the actual word this case renders.
    if !text.contains("status unknown") {
        return Err(format!(
            "expected the unconfirmed-activity wording \"status unknown\": {text:?}"
        ));
    }
    Ok(())
}

/// A helper that answered with a typed error is prominent too, but
/// must not be worded as if the helper could not be reached at all -- the
/// helper answered here.
fn an_errored_reply_is_prominent_but_not_worded_as_unreachable() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusErrored",
        move |_app| {
            let bar = StatusBar::new();
            bar.set_errored("not authorized: com.jacopobriccola.Porthole.List");
            *seen.borrow_mut() = Some((bar.text(), bar.is_prominent()));
        },
    );
    let (text, prominent) = result.borrow_mut().take().ok_or("activation never ran")?;
    if !prominent {
        return Err("an errored reply must not be rendered as an ordinary status line".to_string());
    }
    if text.to_lowercase().contains("could not reach") {
        return Err(format!(
            "the helper answered here -- \"could not reach\" is the other case's claim: {text:?}"
        ));
    }
    if text.contains("already reachable") {
        return Err(format!(
            "an errored reply must not claim reachability either way: {text:?}"
        ));
    }
    if text.to_lowercase().contains("refus") || text.to_lowercase().contains("declin") {
        // This same code path renders a `StateStore` failure inside
        // the helper too, which is not a decision anyone made -- see
        // `status_bar.rs`'s own module doc.
        return Err(format!(
            "the errored reply must not assert a refusal/decision the error may not be: {text:?}"
        ));
    }
    if !text.contains("not authorized") {
        return Err(format!(
            "the helper's own error reason must survive verbatim: {text:?}"
        ));
    }
    Ok(())
}

/// Once the banner takes over, the ordinary line's own real, on-screen
/// text must not still read a stale confirmed claim from an earlier,
/// successful refresh -- `text()` alone cannot catch this (it prefers the
/// revealed banner over the line), so this reads the line widget directly.
fn the_ordinary_line_is_cleared_once_the_banner_takes_over() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusStaleLine",
        move |_app| {
            let bar = StatusBar::new();
            // A good refresh first, so the line carries a real, confirmed claim...
            bar.set_status(&status(Some(("firewalld", "2.4.4")), true));
            let line_before = bar.line_widget().label().to_string();
            // ...then a bad one. The banner takes over; the line must not still
            // say "enforcing" underneath it.
            bar.set_unreachable("could not reach the porthole helper: timed out");
            let line_after = bar.line_widget().label().to_string();
            *seen.borrow_mut() = Some((line_before, line_after));
        },
    );
    let (line_before, line_after) = result.borrow_mut().take().ok_or("activation never ran")?;
    if !line_before.contains("firewalld") {
        return Err(format!(
            "expected the good refresh to have set the line first: {line_before:?}"
        ));
    }
    if !line_after.is_empty() {
        return Err(format!(
            "the ordinary line must be cleared once the banner takes over, still: {line_after:?}"
        ));
    }
    Ok(())
}

/// A residual left by the no-firewall fix: the no-firewall
/// detail sits on the same `gtk::Label` `StatusBar::new` gives `dim-label`/
/// `caption` unconditionally, so the explanation of a prominent warning
/// banner rendered small and grey at the opposite end of the window from the
/// banner it explains. This checks the real widget's own CSS classes, not
/// just its text: the no-firewall case must drop `dim-label`, and an
/// ordinary enforcing refresh -- including one that follows a no-firewall
/// refresh -- must still carry it.
fn the_no_firewall_detail_line_is_not_styled_as_a_dim_caption() -> Result<(), String> {
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.StatusNoFirewallStyling",
        move |_app| {
            let bar = StatusBar::new();
            bar.set_status(&status(None, false));
            let dim_while_no_firewall = bar.line_widget().has_css_class("dim-label");
            bar.set_status(&status(Some(("firewalld", "2.4.4")), true));
            let dim_after_recovering = bar.line_widget().has_css_class("dim-label");
            *seen.borrow_mut() = Some((dim_while_no_firewall, dim_after_recovering));
        },
    );
    let (dim_while_no_firewall, dim_after_recovering) =
        result.borrow_mut().take().ok_or("activation never ran")?;
    if dim_while_no_firewall {
        return Err(
            "the no-firewall detail must not be styled as a dim caption while it is showing"
                .to_string(),
        );
    }
    if !dim_after_recovering {
        return Err(
            "an ordinary enforcing refresh following a no-firewall one must restore the \
             line's usual dim styling"
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
    let cases: [Case; 9] = [
        (
            "the_status_line_names_the_backend_and_whether_it_is_enforcing",
            the_status_line_names_the_backend_and_whether_it_is_enforcing,
        ),
        (
            "no_firewall_at_all_is_prominent_not_a_footnote",
            no_firewall_at_all_is_prominent_not_a_footnote,
        ),
        (
            "the_no_firewall_case_shows_a_short_banner_and_the_full_detail_on_the_line",
            the_no_firewall_case_shows_a_short_banner_and_the_full_detail_on_the_line,
        ),
        (
            "an_installed_but_stopped_firewall_says_stopped_not_missing",
            an_installed_but_stopped_firewall_says_stopped_not_missing,
        ),
        (
            "an_unreachable_helper_is_prominent_but_does_not_claim_reachability",
            an_unreachable_helper_is_prominent_but_does_not_claim_reachability,
        ),
        (
            "a_firewall_porthole_could_not_read_is_not_confused_with_a_confirmed_stop",
            a_firewall_porthole_could_not_read_is_not_confused_with_a_confirmed_stop,
        ),
        (
            "an_errored_reply_is_prominent_but_not_worded_as_unreachable",
            an_errored_reply_is_prominent_but_not_worded_as_unreachable,
        ),
        (
            "the_ordinary_line_is_cleared_once_the_banner_takes_over",
            the_ordinary_line_is_cleared_once_the_banner_takes_over,
        ),
        (
            "the_no_firewall_detail_line_is_not_styled_as_a_dim_caption",
            the_no_firewall_detail_line_is_not_styled_as_a_dim_caption,
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
