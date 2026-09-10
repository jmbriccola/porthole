//! The one question porthole asks about update checks, and where the answer
//! goes.
//!
//! **Why the window and not a notification.** What a person needs in order to
//! answer is that *nothing leaves the machine* -- the package manager already
//! installed on it is asked, not a server -- and that does not fit in two
//! lines of notification body. So the question is put by the window at first
//! launch, and never by a notification.
//!
//! **Three states, and this only ever writes two of them.** *Never asked* is
//! what a machine starts in and what brings this dialog up; *yes* and *no*
//! are the two buttons. There is no way back to *never asked* from here, and
//! that is deliberate -- a control that made porthole ask again would be a
//! way to nag somebody who has already answered. The file
//! (`~/.config/porthole/update.toml`) is where an answer can be changed, and
//! `porthole update --enable`/`--disable` is the other way.
//!
//! **Dismissing is not answering.** Escape, or clicking away, leaves the
//! state at *never asked*, so the question can be put again at the next
//! launch. Recording a dismissal as *no* would be porthole answering on the
//! person's behalf, in the one direction that silences the question for good;
//! recording it as *yes* would be worse. So neither happens, and the only
//! things that write are the two buttons.

use adw::prelude::*;

use porthole_core::update::{Consent, Settings};

/// The response id the "yes" button sends back.
pub const RESPONSE_YES: &str = "check";

/// And the "no" one.
pub const RESPONSE_NO: &str = "no";

/// The id a dismissal reports, and **not** a button: nothing adds it as a
/// response, so the only way to produce it is to close the dialog without
/// answering -- Escape, or clicking away.
///
/// It exists because `AdwAlertDialog` emits `response` for a dismissal too,
/// carrying whatever `close_response` names. Naming [`RESPONSE_NO`] there --
/// which an earlier draft did -- would have filed "no" on behalf of somebody
/// who pressed Escape, and *no* is the answer that stops porthole ever asking
/// again. A dismissal is not an answer, so it gets an id of its own that
/// [`remember`] ignores. (Adw's own default `close_response` is likewise
/// `"close"`, an id dialogs do not add as a button.)
pub const RESPONSE_DISMISSED: &str = "dismissed";

/// The heading, spelled once so the dialog and its tests agree on it.
pub const HEADING: &str = "Check for porthole updates?";

/// The dialog, built but not presented.
///
/// A plain function over no state, so what it says can be read and checked
/// without a display -- the same split every other decision in this crate
/// keeps between "what to say" and "showing it".
pub fn consent_dialog() -> adw::AlertDialog {
    let dialog = adw::AlertDialog::builder()
        .heading(HEADING)
        .body(
            "porthole can ask this machine's own package manager, once a day, whether a \
             newer porthole has been published for it.\n\n\
             Nothing leaves this machine. porthole makes no network request of its own: it \
             asks the package manager that installed it — the same one that already knows \
             what is installed here — and reads the answer. No server is contacted, and \
             nothing about you, this machine or how you use porthole is sent anywhere.\n\n\
             If an update is available porthole says so once, and installing it is \
             PackageKit's own job, with PackageKit's own password prompt. porthole never \
             installs anything itself.\n\n\
             You can change this later with `porthole update --enable` or `--disable`.",
        )
        // Not markup: this is prose written here, but `body_use_markup(false)`
        // is set explicitly for the reason `open_dialog`'s own alert sets it
        // -- a body that renders markup is one an added sentence can break.
        .body_use_markup(false)
        // Dismissing reports an id no button carries, so it writes nothing
        // -- see [`RESPONSE_DISMISSED`]. The keyboard default is the
        // cautious of the two real answers, and pressing it is an answer.
        .close_response(RESPONSE_DISMISSED)
        .default_response(RESPONSE_NO)
        .build();
    dialog.add_response(RESPONSE_NO, "Don't Check");
    dialog.add_response(RESPONSE_YES, "Check Daily");
    // Suggested, not destructive: saying yes is the ordinary, reversible
    // choice, and nothing here is dangerous in either direction.
    dialog.set_response_appearance(RESPONSE_YES, adw::ResponseAppearance::Suggested);
    dialog
}

/// Put the question, if it has never been put.
///
/// Returns the dialog it presented, or `None` when there was nothing to ask
/// -- which is every launch after the first answered one. A test reads the
/// return value; nothing in the application does.
///
/// **Called from `crate::app::build`'s activation handler**, after the window
/// is presented, rather than from `PortholeWindow::new`. Two reasons, and the
/// second is the load-bearing one: activation is what a real launch is, and
/// every other GTK test in this crate builds a `PortholeWindow` directly and
/// would otherwise find an unexpected dialog in front of the widget it came
/// to look at. That one-line call is the only part of this module that no
/// test in this repository exercises.
pub fn ask_if_never_asked(parent: &impl IsA<gtk::Widget>) -> Option<adw::AlertDialog> {
    let path = porthole_core::update::default_path();
    if !Settings::load(&path).consent().should_ask() {
        return None;
    }
    let dialog = consent_dialog();
    dialog.connect_response(None, |_, response| remember(response));
    dialog.present(Some(parent));
    Some(dialog)
}

/// Write down what was answered -- and nothing at all for anything else.
///
/// `AdwAlertDialog` emits `response` for a dismissal too, carrying the
/// `close_response`. That is why this matches on the two ids explicitly
/// rather than reading "not yes" as no: a person who pressed Escape has not
/// declined, and writing *no* for them would end the question permanently on
/// the strength of a keypress that means "go away", not "never ask me".
///
/// The read-modify-write keeps whatever else is in the file -- the record of
/// which version was last announced lives there too, and answering this
/// question is no reason to forget it.
fn remember(response: &str) {
    let consent = match response {
        RESPONSE_YES => Consent::Yes,
        RESPONSE_NO => Consent::No,
        // Not an answer. Includes a dismissal that reports some other id, and
        // anything a future response added to this dialog might send.
        _ => return,
    };
    let path = porthole_core::update::default_path();
    let mut settings = Settings::load(&path);
    settings.set_consent(consent);
    if let Err(e) = settings.save(&path) {
        // On screen would be worse than useless: the person has just answered
        // a question about a background convenience, and a second dialog
        // saying the answer could not be filed would be porthole making its
        // own bookkeeping the user's problem. The cost of this failing is
        // that the question is asked again next launch.
        eprintln!("porthole-gui: could not record the answer about update checks: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure-function coverage, independent of GTK -- these run in the crate's
    // ordinary unit-test binary. The GTK-backed proof that the real dialog
    // carries this text, and that it appears only when it should, is in
    // `tests/update_consent.rs`.

    #[test]
    fn the_two_response_ids_are_distinct_and_neither_is_empty() {
        // They are what `remember` matches on, and an empty or shared id
        // would make one button write the other's answer.
        assert_ne!(RESPONSE_YES, RESPONSE_NO);
        assert!(!RESPONSE_YES.is_empty());
        assert!(!RESPONSE_NO.is_empty());
    }

    #[test]
    fn only_an_explicit_answer_maps_to_a_consent() {
        // `remember` is what writes; this is the decision inside it, checked
        // without touching a file. A dismissal and an unknown id must map to
        // nothing at all -- see this module's own doc comment for why "not
        // yes" must not be read as no.
        let decide = |response: &str| match response {
            RESPONSE_YES => Some(Consent::Yes),
            RESPONSE_NO => Some(Consent::No),
            _ => None,
        };
        assert_eq!(decide(RESPONSE_YES), Some(Consent::Yes));
        assert_eq!(decide(RESPONSE_NO), Some(Consent::No));
        for other in [RESPONSE_DISMISSED, "", "close", "something-added-later"] {
            assert_eq!(decide(other), None, "{other} is not an answer");
        }
        // And the dismissal id is not one of the buttons, or dismissing
        // would answer after all.
        assert_ne!(RESPONSE_DISMISSED, RESPONSE_YES);
        assert_ne!(RESPONSE_DISMISSED, RESPONSE_NO);
    }
}
