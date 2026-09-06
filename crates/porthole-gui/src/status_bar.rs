//! The status line: the one place this window states what firewall the
//! helper reports, and whether it is actually enforcing anything.
//!
//! Two widgets, not one, because what [`StatusBar`] can be asked to show
//! carries very different weight depending on which fact it is. An
//! installed, running (or merely stopped) firewall is [`StatusBar::line`]'s
//! business: a small, dim line at the bottom of the window -- the kind a
//! person reads only if they go looking for it. The absence of any
//! firewall at all is a different fact entirely: every port on this
//! machine is already reachable, and porthole did nothing to cause or
//! prevent that. A grey line at the bottom of the window is not where a
//! fact like that belongs -- the user would read the rest of the app as if
//! it were protecting them. That case, and a helper porthole could not
//! even reach (see below), use [`StatusBar::banner`] instead: an
//! `adw::Banner`, full-width and coloured by libadwaita's own stylesheet
//! (no hex colour of this crate's own -- the whole point is that this
//! reads as urgent in both light and dark without this module deciding a
//! shade), placed just below the header bar rather than buried at the
//! bottom.
//!
//! ## Two facts this must not collapse into one
//!
//! "No firewall is installed" and "porthole could not reach the helper to
//! ask" are not the same fact, and rendering the first when the truth is
//! the second is this project's own characteristic defect, reproduced here
//! at the one screen left that could still make it: the first is a
//! *confirmed* absence (this port genuinely is already reachable, and
//! [`StatusBar::set_status`] says so); the second is an absence of
//! information (the port might be firewalled, might not be -- porthole
//! simply could not find out). [`StatusBar::set_unreachable`] renders the
//! second, and its wording never claims "already reachable" -- that claim
//! belongs only to the case porthole actually confirmed. `tests/status_bar.rs`
//! pins this apart directly: the unreachable-helper text must not contain
//! the reachability claim the no-firewall text does.
//!
//! Both of those are also `enforcing`/`not running`/`status unknown` for a
//! *different* pair of facts: whether a firewall that **is** installed is
//! currently active. `status_active_unknown` (mirroring
//! `porthole-cli`'s own `firewall_active_unknown` -- see
//! `WireStatus`'s own doc comment) keeps "confirmed not running" from
//! being said when the truth is "could not confirm" -- the same collapse,
//! one layer down.

use porthole_core::ipc::WireStatus;

/// [`StatusBar::set_status`]'s no-firewall wording, in one place so the
/// "these two facts must not merge" test in `tests/status_bar.rs` has
/// exactly one string to check [`unreachable_title`] never reproduces.
const NO_FIREWALL_TITLE: &str =
    "No firewall found — every port on this machine is already reachable from your network.";

fn unreachable_title(message: &str) -> String {
    format!("Could not reach the porthole helper — {message}")
}

/// Three states, not two -- see this module's own doc comment on why
/// `active_unknown` cannot be folded into `!active`.
fn state_word(status: &WireStatus) -> &'static str {
    if status.firewall_active {
        "enforcing"
    } else if status.firewall_active_unknown {
        "status unknown"
    } else {
        "not running"
    }
}

/// The backend's name and, when the helper reported one, its version --
/// never a second hardcoded reformatting of fields `WireStatus` already
/// carries separately.
fn backend_name(status: &WireStatus) -> String {
    if status.firewall_version.is_empty() {
        status.backend.clone()
    } else {
        format!("{} {}", status.backend, status.firewall_version)
    }
}

/// The status line: names the firewall backend and whether it is
/// enforcing anything, or -- for the two more serious cases -- says so
/// prominently instead. See this module's own doc comment.
#[derive(Clone)]
pub struct StatusBar {
    /// The ordinary case.
    line: gtk::Label,
    /// The two prominent cases.
    banner: adw::Banner,
}

impl Default for StatusBar {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusBar {
    pub fn new() -> Self {
        let line = gtk::Label::builder()
            .css_classes(["dim-label", "caption"])
            .margin_top(6)
            .margin_bottom(6)
            .build();

        let banner = adw::Banner::new("");

        Self { line, banner }
    }

    /// The real `gtk::Label` `PortholeWindow` places as the toolbar's
    /// bottom bar.
    pub fn line_widget(&self) -> &gtk::Label {
        &self.line
    }

    /// The real `adw::Banner` `PortholeWindow` places as a top bar, right
    /// below the header -- see this module's own doc comment for why the
    /// two prominent cases need a widget the ordinary line cannot be.
    pub fn banner_widget(&self) -> &adw::Banner {
        &self.banner
    }

    /// Renders the helper's own `status`: the backend's name and version
    /// and plainly whether it is enforcing anything, or -- when
    /// `firewall_available` is `false` -- the more serious, confirmed fact
    /// that there is no firewall at all. See this module's own doc comment
    /// for the distinction that must survive between this and
    /// [`StatusBar::set_unreachable`].
    pub fn set_status(&self, status: &WireStatus) {
        if !status.firewall_available {
            self.banner.set_title(NO_FIREWALL_TITLE);
            self.banner.set_revealed(true);
            return;
        }
        self.banner.set_revealed(false);
        self.line.set_label(&format!(
            "{} — {}",
            backend_name(status),
            state_word(status)
        ));
    }

    /// Renders the other prominent case: porthole could not even ask the
    /// helper, so it has no status to report -- not "no firewall", which is
    /// a claim porthole is not in a position to make here. `message` is
    /// the reason, verbatim -- the same string
    /// `OpenNowSection::set_unreachable` receives, from the same failed
    /// round trip.
    pub fn set_unreachable(&self, message: &str) {
        self.banner.set_title(&unreachable_title(message));
        self.banner.set_revealed(true);
    }

    /// The text as it actually reads on screen right now: the banner's own
    /// title while it is the one showing, the line's own label otherwise
    /// -- never a value recomputed independently of the real widgets.
    pub fn text(&self) -> String {
        if self.banner.is_revealed() {
            self.banner.title().to_string()
        } else {
            self.line.label().to_string()
        }
    }

    /// Whether the currently-showing text is the prominent banner rather
    /// than the ordinary line -- reads the real `adw::Banner`'s own
    /// `revealed` property, not a separately tracked flag, so this cannot
    /// drift from what the window actually shows.
    pub fn is_prominent(&self) -> bool {
        self.banner.is_revealed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure-function coverage, independent of GTK -- these run in the
    // crate's ordinary unit-test binary. The GTK-backed proof that the
    // real widgets carry this same text lives in `tests/status_bar.rs`.

    #[test]
    fn the_no_firewall_and_unreachable_titles_never_say_the_same_thing() {
        // Pin: these are two different facts (a confirmed absence of any
        // firewall vs. porthole simply not knowing), and collapsing them
        // into the same sentence is exactly the defect this module's own
        // doc comment describes. If a future edit ever makes
        // `unreachable_title` reuse `NO_FIREWALL_TITLE`'s wording, or vice
        // versa, this fails.
        let unreachable = unreachable_title("could not reach the porthole helper: timed out");
        assert_ne!(unreachable, NO_FIREWALL_TITLE);
        assert!(
            !unreachable.contains("already reachable"),
            "an unreachable helper must not claim reachability either way: {unreachable}"
        );
        assert!(
            NO_FIREWALL_TITLE.contains("already reachable"),
            "the confirmed no-firewall case must still make that claim: {NO_FIREWALL_TITLE}"
        );
    }

    #[test]
    fn state_word_keeps_confirmed_stopped_apart_from_unknown() {
        let mut status = WireStatus {
            backend: "firewalld".to_string(),
            firewall_available: true,
            firewall_active: false,
            firewall_active_unknown: false,
            firewall_version: String::new(),
            location: String::new(),
            interface: String::new(),
            address: String::new(),
            cidr: String::new(),
            rules: Vec::new(),
        };
        assert_eq!(state_word(&status), "not running");
        status.firewall_active_unknown = true;
        assert_eq!(state_word(&status), "status unknown");
        assert_ne!(
            state_word(&status),
            "not running",
            "a confirmed-stopped firewall and one porthole could not read must not print the same word"
        );
    }
}
