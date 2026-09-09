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
//! That reachability claim itself is not this module's own to make, and
//! this took two attempts to get right. The first version of this fix
//! hardcoded the claim as a GUI-authored constant -- true today only
//! because `backend::detect` cannot currently fail any other way, with
//! nothing in the wire type connecting the two. The second put
//! `WireStatus::detail` (`porthole-core`'s own text, verbatim, reaching the
//! wire through `BackendHealth::detail`) directly into the banner's own
//! `title` -- which fixed the first problem and created a different one:
//! `detail` is three sentences, written for a CLI's own per-command error
//! ("**this port** is already reachable... Setting up a firewall is
//! outside what porthole does"), and a window-level banner with a whole
//! paragraph in lowercase-initial CLI register, about a port nobody asked
//! about, is not what "prominent" was ever supposed to mean.
//!
//! [`NO_FIREWALL_TITLE`] is what the banner's own `title` shows now: short,
//! capitalised, authored for this surface, and -- deliberately -- it does
//! not itself claim reachability. The reachability claim -- and the rest of
//! `detail`'s own explanation, unedited -- still reaches the user, verbatim,
//! on [`StatusBar::line`] right underneath: item 5's own principle (the
//! helper's text must reach the user, not a GUI paraphrase resting on an
//! invariant held elsewhere) survives; only which widget carries which half
//! of it changed.
//!
//! `!status.firewall_available` is not, on its own, "no firewall is
//! installed" -- `docs/json-schema.md` documents it as folding that together
//! with "porthole could not detect a backend at all, for whatever reason",
//! and only the first of those is what [`NO_FIREWALL_TITLE`] states. Neither
//! backend health check this project ships can currently produce the second
//! case (nothing here claims a future one never will), so `status.detail`
//! today is always [`porthole_core::backend::NO_FIREWALL_MESSAGE`] itself
//! whenever `firewall_available` is `false` -- but the banner title is
//! chosen by checking that, not by assuming it: `set_status` shows
//! [`NO_FIREWALL_TITLE`] only when `detail` actually is that message, and a
//! separate, honestly-uncertain title otherwise.
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
//! And a fourth, for the reason the third exists: an answer that arrived
//! and that this build could not **read**, because the helper is built
//! against a different shape of the same wire type.
//! [`StatusBar::set_undecodable`] is that case. It used to reach
//! [`StatusBar::set_unreachable`] -- a `SignatureMismatch` is not a
//! `MethodError`, so it fell through to it -- and this window told a person
//! it could not reach a helper that had just replied. Its title is split
//! from its detail the way the no-firewall case is: the short sentence a
//! person can act on in the banner, and zbus's own text naming the two
//! signatures on the line underneath, verbatim.
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

use adw::prelude::*;
use porthole_core::backend::NO_FIREWALL_MESSAGE;
use porthole_core::ipc::{Alignment, WireStatus};

/// [`StatusBar::set_status`]'s title for a confirmed no-firewall detection
/// -- short, and deliberately makes no claim beyond that. See this module's
/// own doc comment for why the stronger "already reachable" claim belongs
/// on [`StatusBar::line`] instead, verbatim from `status.detail`, not
/// repeated or paraphrased here, and for why this is not simply what
/// `!status.firewall_available` means on its own.
const NO_FIREWALL_TITLE: &str = "No firewall detected.";

/// [`StatusBar::set_status`]'s title for `!status.firewall_available` when
/// `status.detail` is not [`NO_FIREWALL_MESSAGE`] -- the second fact that
/// bit folds together (see this module's own doc comment) and the one
/// [`NO_FIREWALL_TITLE`] must not be shown for, since porthole did not
/// confirm it.
const COULD_NOT_DETERMINE_TITLE: &str = "Could not determine whether a firewall is installed.";

/// Picks between [`NO_FIREWALL_TITLE`] and [`COULD_NOT_DETERMINE_TITLE`] by
/// checking `status.detail` against [`NO_FIREWALL_MESSAGE`] directly, rather
/// than assuming `!status.firewall_available` always means the confirmed
/// case -- see this module's own doc comment.
fn no_firewall_banner_title(status: &WireStatus) -> &'static str {
    if status.detail == NO_FIREWALL_MESSAGE {
        NO_FIREWALL_TITLE
    } else {
        COULD_NOT_DETERMINE_TITLE
    }
}

fn unreachable_title(message: &str) -> String {
    format!("Could not reach the porthole helper — {message}")
}

/// The fourth prominent case, and the only one that is about this window
/// rather than about the helper: the helper answered, and this build could
/// not **read** the answer -- see `window.rs`'s own `HelperFailure` doc
/// comment, and `porthole_core::ipc::is_undecodable` for what is measured
/// behind it.
///
/// Short, authored for this surface, and split the way
/// [`NO_FIREWALL_TITLE`] is split from `status.detail`: this sentence is
/// what a person can act on, and the zbus text that names the two
/// signatures goes on [`StatusBar::line`] underneath, verbatim, rather than
/// into a banner nobody could read at a glance.
///
/// It does not say "could not reach": the helper answered.
///
/// **This one names both remedies, and the two below name one.** A signature
/// mismatch names two signatures and does not order them, which is what this
/// wording is for -- and it is still the honest wording whenever the helper's
/// own `porthole_core::ipc::PROTOCOL_VERSION` could not be read, and when two
/// binaries report the same version and still cannot read each other (a
/// signature moved without the number moving, which
/// `porthole_core::ipc::CONTRACTS` commits the two as a pair to keep out of
/// a release, and which if it happened anyway would mean the number is
/// evidence of nothing).
const UNDECODABLE_TITLE: &str =
    "Porthole and the porthole helper are different versions, so this window cannot read \
     what it answers. Close and reopen this window; if that does not help, restart \
     porthole-helper.service.";

/// The helper's own version says it is the older half: the remedy is a
/// system service, and this window cannot restart one.
const HELPER_IS_OLDER_TITLE: &str =
    "The porthole helper is an older version than this window, so this window cannot read \
     what it answers. Restart it: `systemctl restart porthole-helper.service`.";

/// This window is the older half.
///
/// **It does not offer to restart itself, and that is the recorded choice
/// for this component** (`docs/superpowers/specs/2026-09-09-update-notifier-
/// design.md`: «La GUI aperta non può ri-eseguirsi mentre è in uso. Se ne
/// accorge e lo dice»). `porthole-agent` does re-execute itself, because
/// nothing is looking at it; a window is something a person arranged on a
/// screen, and one that vanished and came back under their hands would have
/// reported nothing.
const THIS_WINDOW_IS_OLDER_TITLE: &str =
    "This window is an older version of porthole than the helper it is talking to, so it \
     cannot read what the helper answers. Close and reopen it to start the version that \
     is installed now.";

/// Which of the three [`StatusBar::set_undecodable`] shows.
fn undecodable_title(alignment: Option<Alignment>) -> &'static str {
    match alignment {
        Some(Alignment::HelperIsOlder) => HELPER_IS_OLDER_TITLE,
        Some(Alignment::ThisOneIsOlder) => THIS_WINDOW_IS_OLDER_TITLE,
        Some(Alignment::Same) | None => UNDECODABLE_TITLE,
    }
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
        // `wrap`/`max_width_chars` matter now in a way they did not before
        // this task: the ordinary enforcing/not-running line is always
        // short, but `set_status`'s no-firewall case puts `WireStatus::
        // detail` here too -- porthole-core's own no-firewall sentence is
        // 248 characters. Confirmed in a container, by rendering it: an
        // unwrapped label does not truncate or scroll, it makes the
        // *window* as wide as the whole unbroken line demands (`AdwToolbarView
        // ... exceeds AdwApplicationWindow width: requested 1234 px, 470 px
        // available`, and the window itself grew to match) -- the label
        // wrapping is what keeps a long `detail` from doing that again.
        let line = gtk::Label::builder()
            .css_classes(["dim-label", "caption"])
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(12)
            .margin_end(12)
            .wrap(true)
            .wrap_mode(gtk::pango::WrapMode::WordChar)
            .justify(gtk::Justification::Center)
            .max_width_chars(60)
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
    /// `firewall_available` is `false` -- one of two more serious banners,
    /// chosen from `status.detail` (see this module's own doc comment for
    /// why `firewall_available: false` alone does not settle which). See
    /// this module's own doc comment for the distinction that must survive
    /// between either of those and [`StatusBar::set_unreachable`].
    ///
    /// The no-firewall case is the one place `line` is used *alongside* a
    /// revealed banner rather than cleared by it: `show_banner` clears
    /// `line` first (as it does for the other two prominent cases, so a
    /// stale confirmed claim cannot linger), and this then immediately
    /// gives `line` new, current content of its own -- `status.detail`,
    /// verbatim -- rather than leaving it empty. See this module's own doc
    /// comment for why the detail belongs here and not in the banner's own
    /// title.
    pub fn set_status(&self, status: &WireStatus) {
        if !status.firewall_available {
            self.show_banner(no_firewall_banner_title(status));
            self.line.set_label(&status.detail);
            // `show_banner` restores `dim-label` (the ordinary line's
            // default styling) along with clearing the text -- wrong here:
            // `status.detail` is the explanation of the banner sitting at
            // the opposite end of the window, not an ordinary dim caption,
            // and rendering it small and grey made it easy for the eye to
            // never connect the two. See this module's own doc comment.
            self.line.remove_css_class("dim-label");
            return;
        }
        self.banner.set_revealed(false);
        self.line.set_label(&format!(
            "{} — {}",
            backend_name(status),
            state_word(status)
        ));
        // The ordinary case always restores the dim styling -- a caller
        // going no-firewall -> installed-and-active must not leave the line
        // looking like it is still explaining a banner that is gone.
        self.line.add_css_class("dim-label");
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

    /// The fourth prominent case: the helper answered and this build could
    /// not read the answer -- see [`UNDECODABLE_TITLE`]. `message` is the
    /// zbus text naming the two signatures, and it goes on the line
    /// underneath rather than into the banner, the same split
    /// [`StatusBar::set_status`]'s no-firewall branch makes and for the same
    /// reason.
    ///
    /// `alignment` is what the helper's own version said about which of the
    /// two is behind, and it decides which of the three wordings above the
    /// banner carries -- one remedy where the version identified a half, and
    /// both where it did not. `None` is a version that could not be read at
    /// all.
    pub fn set_undecodable(&self, message: &str, alignment: Option<Alignment>) {
        self.show_banner(undecodable_title(alignment));
        self.line.set_label(message);
        // Not a dim caption: it is the detail of the banner at the other end
        // of the window, exactly as `status.detail` is.
        self.line.remove_css_class("dim-label");
    }

    /// Shared by all three prominent cases: reveals the banner with
    /// `title`, and clears the ordinary line's own text. Without the
    /// second half, a confirmed claim from an earlier, successful refresh
    /// (`"firewalld 2.4.4 — enforcing"`) would keep reading on screen
    /// underneath a banner now saying the helper cannot even be reached --
    /// `text()` would not show it (it prefers the revealed banner), but the
    /// line widget itself, real and still visible in the toolbar's bottom
    /// bar, would. `set_status`'s own no-firewall branch is the one caller
    /// that gives `line` new content of its own immediately afterward
    /// (`status.detail`) rather than leaving it cleared -- see that
    /// method's own doc comment.
    fn show_banner(&self, title: &str) {
        self.banner.set_title(title);
        self.banner.set_revealed(true);
        self.line.set_label("");
        // Restores the line's ordinary dim styling -- `set_status`'s own
        // no-firewall branch is the one caller that immediately removes it
        // again, since that is the one case where `line` goes on to carry
        // meaningful text of its own (see this module's own doc comment).
        // For the other two callers the line is empty anyway, but leaving
        // this unconditional keeps a stale non-dim style from surviving
        // into whichever case runs next.
        self.line.add_css_class("dim-label");
    }

    /// The banner's own title while it is the one showing, the line's own
    /// label otherwise -- never a value recomputed independently of the
    /// real widgets. Not literally everything on screen: the one case
    /// where both widgets carry meaningful text at once is the no-firewall
    /// banner (see [`StatusBar::set_status`]), where `line` also holds
    /// `status.detail` -- read [`StatusBar::line_widget`] directly for
    /// that, the way `tests/status_bar.rs` does.
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
    fn the_no_firewall_title_does_not_itself_claim_reachability() {
        // Item 6 (round 3): the banner's own short title must not
        // independently assert "already reachable" -- that would rest the
        // claim on a GUI-authored sentence again, the exact thing item 5
        // fixed once already. The claim belongs to `status.detail`,
        // verbatim, on `line` -- see `the_no_firewall_banner_shows_a_short_
        // title_with_the_full_detail_on_the_line` in `tests/status_bar.rs`
        // for the real widgets carrying that split.
        assert!(
            !NO_FIREWALL_TITLE.to_lowercase().contains("reachable"),
            "the banner title must not itself claim reachability: {NO_FIREWALL_TITLE}"
        );
    }

    /// The fixture `docs/json-schema.md` describes as not live today:
    /// `firewall_available: false` with a `detail` that is not
    /// `NO_FIREWALL_MESSAGE`. This must not render as the confirmed
    /// `NO_FIREWALL_TITLE` -- porthole did not confirm that in this case.
    fn status_with_detail(detail: &str) -> WireStatus {
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
    fn the_no_firewall_title_is_used_only_when_detail_confirms_it() {
        let confirmed = status_with_detail(NO_FIREWALL_MESSAGE);
        assert_eq!(no_firewall_banner_title(&confirmed), NO_FIREWALL_TITLE);

        let ambiguous = status_with_detail("could not read /proc/net/dev: permission denied");
        assert_eq!(
            no_firewall_banner_title(&ambiguous),
            COULD_NOT_DETERMINE_TITLE,
            "a detail that is not NO_FIREWALL_MESSAGE must not be shown under the \
             confirmed-absence title"
        );
        assert_ne!(COULD_NOT_DETERMINE_TITLE, NO_FIREWALL_TITLE);
    }

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
    }

    #[test]
    fn an_errored_reply_is_worded_apart_from_both_other_cases() {
        // I2: a helper that answered with a typed error is a third fact,
        // not a rewording of "could not reach" or "no firewall". Pins all
        // three titles apart the same way the test above pins the first two.
        let errored = errored_title("not authorized: com.jacopobriccola.Porthole.List");
        let unreachable = unreachable_title("could not reach the porthole helper: timed out");
        assert_ne!(errored, unreachable);
        assert_ne!(errored, NO_FIREWALL_TITLE);
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
    fn a_message_this_build_cannot_read_is_a_fourth_wording_and_claims_no_unreachability() {
        // The fourth fact, pinned apart from the other three exactly as they
        // are pinned apart from each other. The helper answered -- "could
        // not reach" is the other case's claim, and it is the one the GUI
        // actually made for this before, since a `SignatureMismatch` is not
        // a `MethodError` and fell straight through to `Unreachable`.
        let unreachable = unreachable_title("could not reach the porthole helper: timed out");
        let errored = errored_title("not authorized: com.jacopobriccola.Porthole.List");
        assert_ne!(UNDECODABLE_TITLE, unreachable);
        assert_ne!(UNDECODABLE_TITLE, errored);
        assert_ne!(UNDECODABLE_TITLE, NO_FIREWALL_TITLE);
        assert!(
            !UNDECODABLE_TITLE.to_lowercase().contains("could not reach"),
            "the helper answered here: {UNDECODABLE_TITLE}"
        );
        assert!(
            !UNDECODABLE_TITLE.to_lowercase().contains("reachable"),
            "and this says nothing about whether any port is: {UNDECODABLE_TITLE}"
        );
        // Both remedies, since nothing on the wire says which half is older.
        assert!(
            UNDECODABLE_TITLE.contains("porthole-helper.service"),
            "{UNDECODABLE_TITLE}"
        );
        assert!(
            UNDECODABLE_TITLE
                .to_lowercase()
                .contains("reopen this window"),
            "{UNDECODABLE_TITLE}"
        );
    }

    #[test]
    fn the_banner_names_the_one_remedy_the_helpers_own_version_identified() {
        // What the protocol version bought this window. The wording above
        // offers two remedies and asks the person to try them in turn; with
        // a version on the wire, two of the three cases know which one it
        // is.
        let helper_older = undecodable_title(Some(Alignment::HelperIsOlder));
        assert!(
            helper_older.contains("systemctl restart porthole-helper.service"),
            "{helper_older}"
        );
        assert!(
            !helper_older.to_lowercase().contains("reopen this window"),
            "reopening this window would start the same version again: {helper_older}"
        );

        let window_older = undecodable_title(Some(Alignment::ThisOneIsOlder));
        assert!(
            window_older.to_lowercase().contains("reopen"),
            "the window's own remedy, which is the one it cannot perform for itself: \
             {window_older}"
        );
        assert!(
            !window_older.contains("porthole-helper.service"),
            "restarting the newer half would change nothing: {window_older}"
        );

        // Nothing known keeps the wording from before there was a version,
        // and so does an equal version that is nonetheless unreadable --
        // that combination means a signature moved without the number
        // moving, so the number is evidence of nothing.
        assert_eq!(undecodable_title(None), UNDECODABLE_TITLE);
        assert_eq!(undecodable_title(Some(Alignment::Same)), UNDECODABLE_TITLE);

        // Three wordings, not one wording three times -- and none of them
        // claims the helper could not be reached, which is the false claim
        // this whole case exists to have stopped making.
        assert_ne!(helper_older, window_older);
        assert_ne!(helper_older, UNDECODABLE_TITLE);
        assert_ne!(window_older, UNDECODABLE_TITLE);
        for title in [helper_older, window_older] {
            assert!(!title.to_lowercase().contains("could not reach"), "{title}");
            assert!(title.contains("cannot read"), "{title}");
        }
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
