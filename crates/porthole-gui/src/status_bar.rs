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
//! ## Facts this must not collapse into one another
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
//! That reachability claim itself is not this module's own to make.
//! [`no_firewall_title`] shows `WireStatus::detail` verbatim -- the exact
//! sentence `porthole-core`'s own `backend::detect` failure carries, the
//! same one `porthole-cli`'s `print_status`/`--json` already show -- rather
//! than a GUI-authored sentence that merely happens to be true today
//! because `detect` cannot currently fail any other way. An earlier
//! version of this module hardcoded that sentence as a constant, which
//! rested the "already reachable" claim on an invariant held entirely in
//! `porthole-core`, with nothing in the wire type connecting the two: if a
//! future `detect` failure mode ever stopped confirming reachability, this
//! module would have kept claiming it anyway. Showing `detail` verbatim
//! means this module states only what the helper actually said.
//!
//! A third fact needs its own wording too, for the identical reason: a
//! helper that *did* answer, but with a typed error, is not "could not
//! reach" either -- [`StatusBar::set_errored`] is that third case, and its
//! title never borrows either of the other two's wording. It also does not
//! claim *why* the helper's answer was an error: a polkit denial is one
//! cause, but `list` and `status` can just as well fail with a
//! `StateStore` read error inside the helper, which is not a decision
//! anyone made to decline anything -- see `window.rs`'s own `HelperFailure`
//! doc comment, which this module's wording is deliberately built to stay
//! honest about (an earlier version of this case was named and worded as a
//! refusal, which was true of a polkit denial and false of everything
//! else that reaches the same code path).
//!
//! The ordinary line carries a second, unrelated distinction:
//! `enforcing`/`not running`/`status unknown`, for a *different* pair of
//! facts than any of the three above -- whether a firewall that **is**
//! installed is currently active. `firewall_active_unknown` (a field on
//! `WireStatus`, `porthole_core::ipc` -- the same distinction
//! `porthole-cli`'s own local `--json` output already carries under the
//! identical name) keeps "confirmed not running" from being said when the
//! truth is "could not confirm". The banner never shows this three-way
//! word at all: each of its own three cases is already the more serious
//! fact, one layer up, and [`StatusBar::show_banner`] clears the line
//! whenever the banner takes over, so a stale confirmed claim from a
//! previous, better refresh cannot linger underneath it.

use porthole_core::ipc::WireStatus;

/// [`StatusBar::set_status`]'s no-firewall wording: `status.detail`,
/// verbatim -- see this module's own doc comment for why this must not be
/// a sentence of this module's own invention. `detail` is never empty in
/// practice (every `BackendHealth` this codebase constructs sets it, see
/// its own doc comment in `porthole-core`), but a client must not assume
/// the wire will always honour that -- the fallback here is neutral and,
/// unlike the sentence an earlier version of this function hardcoded,
/// does not claim reachability porthole has not actually confirmed.
fn no_firewall_title(status: &WireStatus) -> String {
    if status.detail.is_empty() {
        "No firewall detected.".to_string()
    } else {
        status.detail.clone()
    }
}

fn unreachable_title(message: &str) -> String {
    format!("Could not reach the porthole helper — {message}")
}

/// [`StatusBar::set_errored`]'s wording -- deliberately not built from
/// [`unreachable_title`] or a shared prefix with it: the helper answered
/// here, so "could not reach" would be a claim this case does not support.
/// Also deliberately does not say "refused" or "declined": see this
/// module's own doc comment for why that would overclaim intent for a
/// `StateStore` failure inside the helper.
fn errored_title(message: &str) -> String {
    format!("The porthole helper reported an error — {message}")
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
            self.show_banner(&no_firewall_title(status));
            return;
        }
        self.banner.set_revealed(false);
        self.line.set_label(&format!(
            "{} — {}",
            backend_name(status),
            state_word(status)
        ));
    }

    /// Renders one of the three prominent cases: porthole could not even
    /// ask the helper, so it has no status to report -- not "no firewall",
    /// which is a claim porthole is not in a position to make here, and not
    /// [`StatusBar::set_errored`], which is what a helper that *did*
    /// answer gets instead. `message` is the reason, verbatim -- the same
    /// string `OpenNowSection::set_unreachable` receives, from the same
    /// failed round trip.
    pub fn set_unreachable(&self, message: &str) {
        self.show_banner(&unreachable_title(message));
    }

    /// The other prominent failure case besides "unreachable": the helper
    /// was reached and answered, and the answer was a typed error --
    /// `message` is the helper's own text, verbatim, never wrapped in
    /// "could not reach" (see this module's own doc comment for why
    /// folding this into [`StatusBar::set_unreachable`] would be the
    /// identical collapse one layer further down) and never worded as a
    /// refusal (see the same doc comment for why that would overclaim
    /// intent this case does not always have).
    pub fn set_errored(&self, message: &str) {
        self.show_banner(&errored_title(message));
    }

    /// Shared by all three prominent cases: reveals the banner with
    /// `title`, and clears the ordinary line's own text. Without the
    /// second half, a confirmed claim from an earlier, successful refresh
    /// (`"firewalld 2.4.4 — enforcing"`) would keep reading on screen
    /// underneath a banner now saying the helper cannot even be reached --
    /// `text()` would not show it (it prefers the revealed banner), but the
    /// line widget itself, real and still visible in the toolbar's bottom
    /// bar, would.
    fn show_banner(&self, title: &str) {
        self.banner.set_title(title);
        self.banner.set_revealed(true);
        self.line.set_label("");
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

    /// A `WireStatus` with `firewall_available: false` and `detail` set to
    /// `detail` -- everything else is irrelevant to `no_firewall_title`.
    fn no_firewall_status(detail: &str) -> WireStatus {
        WireStatus {
            backend: String::new(),
            firewall_available: false,
            firewall_active: false,
            firewall_active_unknown: false,
            firewall_version: String::new(),
            detail: detail.to_string(),
            location: String::new(),
            interface: String::new(),
            address: String::new(),
            cidr: String::new(),
            rules: Vec::new(),
        }
    }

    #[test]
    fn no_firewall_title_shows_the_wires_own_detail_verbatim() {
        // Item 5: this must be the helper's own text, not a sentence this
        // module invented and merely hoped stayed true -- see this
        // module's own doc comment.
        let detail = "no firewall found: none of firewalld, ufw or nftables is installed. \
                       Without a firewall this port is already reachable from your network.";
        assert_eq!(no_firewall_title(&no_firewall_status(detail)), detail);
    }

    #[test]
    fn no_firewall_title_falls_back_to_a_neutral_sentence_when_detail_is_empty() {
        // `BackendHealth::detail` is never empty in practice, but this
        // function must not assume the wire will always honour that by
        // falling back to a claim ("already reachable") it cannot support
        // without a `detail` to have gotten that claim from.
        let title = no_firewall_title(&no_firewall_status(""));
        assert!(!title.is_empty());
        assert!(
            !title.contains("already reachable"),
            "with no detail to have said so, the fallback must not claim reachability: {title}"
        );
    }

    #[test]
    fn the_no_firewall_and_unreachable_titles_never_say_the_same_thing() {
        // Pin: these are two different facts (a confirmed absence of any
        // firewall vs. porthole simply not knowing), and collapsing them
        // into the same sentence is exactly the defect this module's own
        // doc comment describes. If a future edit ever makes
        // `unreachable_title` reuse `no_firewall_title`'s wording, or vice
        // versa, this fails.
        let no_firewall = no_firewall_title(&no_firewall_status(
            "no firewall found: none of firewalld, ufw or nftables is installed. Without a \
             firewall this port is already reachable from your network.",
        ));
        let unreachable = unreachable_title("could not reach the porthole helper: timed out");
        assert_ne!(unreachable, no_firewall);
        assert!(
            !unreachable.contains("already reachable"),
            "an unreachable helper must not claim reachability either way: {unreachable}"
        );
        assert!(
            no_firewall.contains("already reachable"),
            "the confirmed no-firewall case must still make that claim: {no_firewall}"
        );
    }

    #[test]
    fn an_errored_reply_is_worded_apart_from_both_other_cases() {
        // I2: a helper that answered with a typed error is a third fact,
        // not a rewording of "could not reach" or "no firewall". Pins all
        // three titles apart the same way the test above pins the first two.
        let errored = errored_title("not authorized: com.jacopobriccola.Porthole.List");
        let unreachable = unreachable_title("could not reach the porthole helper: timed out");
        let no_firewall = no_firewall_title(&no_firewall_status(
            "no firewall found: none of firewalld, ufw or nftables is installed. Without a \
             firewall this port is already reachable from your network.",
        ));
        assert_ne!(errored, unreachable);
        assert_ne!(errored, no_firewall);
        assert!(
            !errored.contains("already reachable"),
            "an errored reply must not claim reachability either way: {errored}"
        );
        assert!(
            !errored.to_lowercase().contains("could not reach"),
            "the helper answered here -- \"could not reach\" is the other case's claim: {errored}"
        );
        assert!(
            errored.contains("not authorized"),
            "the helper's own error reason must survive verbatim: {errored}"
        );
    }

    #[test]
    fn the_errored_title_does_not_assert_a_refusal() {
        // I4: a `StateStore` failure inside the helper reaches this exact
        // rendering too (see `window.rs`'s own `classify_failure`), and it
        // is not a decision anyone made to decline anything -- pinning
        // that the wording never claims otherwise, regardless of what the
        // underlying, verbatim message happens to say.
        let errored = errored_title("could not read /run/porthole/state.json: permission denied");
        assert!(
            !errored.to_lowercase().contains("refus"),
            "the errored title must not claim a refusal: {errored}"
        );
        assert!(
            !errored.to_lowercase().contains("declin"),
            "the errored title must not claim a decision to decline: {errored}"
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
            detail: String::new(),
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
