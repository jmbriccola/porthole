//! What a closed rule looks like as a desktop notification, and the session
//! bus interface that shows one.
//!
//! Everything that decides *what* to say is a plain function over a
//! [`WireRule`] and a [`CloseReason`], with no bus anywhere near it, so the
//! wording and the filtering are testable without a notification daemon. Only
//! [`NotificationsProxy`] and [`show`] touch the session bus.

use porthole_core::ipc::{Alignment, CloseReason, WireRule};
use std::collections::HashMap;
use zbus::zvariant::Value;

/// What porthole calls itself to the notification server.
const APP_NAME: &str = "Porthole";

/// The icon name the desktop files already install.
const APP_ICON: &str = "com.jacopobriccola.Porthole";

/// `-1` is the specification's own "let the server decide" sentinel for
/// `expire_timeout`, not a duration porthole picked.
const SERVER_DEFAULT_TIMEOUT: i32 = -1;

/// `0` for `replaces_id` means "a new notification", not "replace number
/// zero". porthole never replaces one: two ports closing are two things that
/// happened, and collapsing them would hide one.
const NEW_NOTIFICATION: u32 = 0;

/// The action key a reopen click comes back as, in `ActionInvoked`'s second
/// argument.
pub const REOPEN: &str = "reopen";

/// One notification, decided but not yet sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub summary: String,
    pub body: String,
    /// `(key, label)` pairs. The key is what `ActionInvoked` sends back; the
    /// label is what the user reads. Empty when there is nothing useful to
    /// offer, which is not the same as offering a button that does nothing.
    pub actions: Vec<(String, String)>,
}

impl Notification {
    /// The `as` argument `Notify` takes: key, label, key, label, ...
    fn action_pairs(&self) -> Vec<&str> {
        self.actions
            .iter()
            .flat_map(|(key, label)| [key.as_str(), label.as_str()])
            .collect()
    }
}

/// Whether a broadcast is this user's business.
///
/// Every signal on the system bus reaches every agent on the machine. A rule
/// carries the uid that opened it, and that is the only thing that decides
/// this: a notification about a port somebody else opened is not addressed
/// to the person reading it, and the `Reopen` on it would not be theirs to
/// answer.
///
/// It is not a confidentiality boundary. `list` is authorized for every
/// user, so which ports porthole has open is already readable by anyone on
/// the machine, and this filter neither adds to that nor takes from it.
pub fn should_notify(rule: &WireRule, uid: u32) -> bool {
    rule.uid == uid
}

/// Whether a close of this kind is worth interrupting the user for.
///
/// [`CloseReason::Requested`] is not: somebody asked for it, in a client that
/// reported the result. Every other reason happened with nobody asking, which
/// is the whole reason this binary exists.
///
/// The signal does not say *who* asked, only that someone did, so a
/// `requested` close of this user's rule from another account is suppressed by
/// this too.
pub fn is_worth_announcing(reason: CloseReason) -> bool {
    !matches!(reason, CloseReason::Requested)
}

/// What the rule was, named so that a reader can act on it: an ordinary
/// open, or a redirect into a container.
///
/// **One subject, four sentences.** A forward expires, is closed on
/// request, is closed when the machine leaves the subnet it was scoped to,
/// and is dropped by reconciliation, exactly as an open is — and until this
/// existed, only the first of those four said so. The other three read as
/// an open: a person is told traffic was being let through to something on
/// this machine when it was being redirected into a container. That is the
/// identical collapse `porthole-gui`'s own `open_now.rs` was changed to stop
/// making on the row, beside this very button.
///
/// It is one function rather than a second arm per reason for the reason
/// `anyone_note` is one function: four wordings of one distinction are four
/// things that can go stale separately, and this file already carried two of
/// them.
///
/// The em dashes are inside the phrase so that every sentence below reads
/// with or without it: `{subject} has expired`, `{subject} was closed on
/// request`.
fn subject(rule: &WireRule) -> String {
    let port = format!("{}/{}", rule.port, rule.protocol);
    if rule.redirects() {
        format!(
            "{port} towards {} — a redirect into the container publishing {} on this \
             machine — ",
            rule.target, rule.published_port
        )
    } else {
        format!("{port} towards {} ", rule.target)
    }
}

/// What to say about a rule that has stopped being open.
///
/// Total over every reason, including the one [`is_worth_announcing`] filters
/// out, so a reason added to the wire enum has to come here and say what it
/// looks like rather than falling into a catch-all.
///
/// Two reasons offer `reopen`, and the test for which is whether re-sending
/// the request can still mean what it meant.
///
/// An expiry can: nothing about the machine changed under the rule, the
/// clock the user set ran out, so re-sending the same request restores what
/// they asked for. [`CloseReason::TargetGone`] can too, and this is the
/// non-obvious one. The request behind a forward names a *published port* --
/// a service on this machine -- never a container address; the address is
/// resolved by the helper, against Docker's own table, at the moment it
/// acts. So a container that restarted somewhere else is not something the
/// stored request pointed at and lost: it is something the request would
/// find again. That is exactly what re-sending it does, and it is why the
/// rule was closed rather than re-aimed in the first place -- porthole
/// re-resolves, it does not assume.
///
/// The other two cannot. After a network change the machine is somewhere
/// else, and a rule for a subnet it has left would appear to work and reach
/// nobody -- the request names that subnet, and no re-resolution can make it
/// the one this machine is on. After a reconciliation something outside
/// porthole removed the rule from the firewall, and this cannot tell what:
/// putting it back at one click, before the user has seen what took it away,
/// would be porthole arguing with whatever that was.
///
/// A `Reopen` on a forward re-sends a **forward**, not an `open` -- see
/// `crate::reopen_request` in `main.rs`, which is where that is decided and
/// where the harm of getting it wrong is spelled out.
pub fn notification_for(rule: &WireRule, reason: CloseReason) -> Notification {
    let port = format!("{}/{}", rule.port, rule.protocol);
    let subject = subject(rule);
    match reason {
        CloseReason::Expired => Notification {
            summary: format!("Port {port} closed"),
            body: format!("{subject}has expired and is closed again."),
            actions: vec![(REOPEN.to_string(), "Reopen".to_string())],
        },
        CloseReason::NetworkChanged => Notification {
            summary: format!("Port {port} closed"),
            body: format!(
                "{subject}was for a network this machine is no longer on, so porthole \
                 closed it."
            ),
            actions: Vec::new(),
        },
        CloseReason::Reconciled => Notification {
            summary: format!("Port {port} was already closed"),
            body: format!(
                "{subject}was gone from the firewall before porthole looked: the rule was \
                 no longer there, so porthole dropped its record of it. Nothing was \
                 removed from the firewall."
            ),
            actions: Vec::new(),
        },
        CloseReason::Requested => Notification {
            summary: format!("Port {port} closed"),
            body: format!("{subject}was closed on request."),
            actions: Vec::new(),
        },
        CloseReason::TargetGone => Notification {
            summary: format!("Port {port} closed"),
            body: format!(
                "{port} was redirected to a container that is no longer the one it was \
                 created for, so porthole closed it rather than re-aiming it: container \
                 addresses change when a container restarts, and the one at that address \
                 now may be a different service. Reopening asks for the forward again and \
                 resolves the container as it is now."
            ),
            actions: vec![(REOPEN.to_string(), "Reopen".to_string())],
        },
    }
}

/// The session bus service every desktop notification goes through.
///
/// `Notify`'s signature here is the one this machine's own bus reports,
/// `susssasa{sv}i` returning `u`, and `ActionInvoked`/`NotificationClosed`
/// are `us`/`uu`. It is a well-known specification, but these were read off a
/// live bus rather than transcribed from it.
#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
pub trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    /// The user clicked one of the buttons. The `s` is the key from
    /// [`Notification::actions`], not the label.
    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: &str) -> zbus::Result<()>;

    /// The notification is gone -- dismissed, expired, or acted on. The `u`
    /// reason is not read: this is only ever the cue to stop holding what the
    /// notification was about.
    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

/// What to say when this agent could not take the session name and so is not
/// going to announce anything.
///
/// On screen rather than only in the journal, and that is the whole point of
/// it. The failure it reports is silent by construction: the agent exits, the
/// unit is `inactive (dead)` as it would be after any ordinary start-up
/// refusal, and nothing closes or misbehaves -- ports still open and close on
/// time, they are simply announced by whatever holds the name, if it still
/// can. A user found out by opening the journal, which is not a thing anyone
/// does unprompted.
///
/// **What is actually known**, and the wording says no more: some other
/// connection holds the name and would not give it up. An agent of this
/// version always gives it up -- that is what `AllowReplacement` in
/// `claim_session` means -- so the holder is not one, and an older one left
/// running is by far the likeliest thing it is. "Most likely" and not "is":
/// nothing here has asked the bus who owns the name.
///
/// No action button. The agent shows this on its way out, so there would be
/// nobody left to answer a click.
pub fn stale_agent_notice() -> Notification {
    Notification {
        summary: "Porthole notifications did not start".to_string(),
        body: "Another process already holds porthole's session name and would not give \
               it up. A current porthole-agent always would, so this is most likely an \
               older one still running from before an upgrade. Log out and back in, or \
               stop that process, to get notifications again."
            .to_string(),
        actions: Vec::new(),
    }
}

/// What to say when this agent cannot read what the helper sends, and is
/// therefore stopping rather than announcing nothing.
///
/// On screen for the same reason [`stale_agent_notice`] is, and the failure
/// it reports is the one that made that notice necessary in the first place:
/// a user upgraded, an agent from before the upgrade went on running, and no
/// close was announced at any point afterwards, in silence. `crate::
/// announce_undecodable` is where the decision to stop is argued.
///
/// **What is actually known**, and the wording claims no more: a message
/// arrived from the helper that this binary could not read, plus whatever
/// `alignment` says. A signature mismatch names two signatures and does not
/// order them, so on its own it cannot say **which of them is older** --
/// which is what `porthole_core::ipc::PROTOCOL_VERSION` was put on the wire
/// for, and what `alignment` carries here.
///
/// - `Some(HelperIsOlder)`: the helper's own version says it is the half
///   left over from the upgrade, and restarting it needs privilege.
/// - `Some(ThisOneIsOlder)`: this agent is. It replaces itself when it
///   finds that out (`crate::replace_this_agent`), so reaching this notice
///   means that did not resolve it -- the installed agent is the old one,
///   or could not be started at all, and the journal says which.
/// - `None`, and `Some(Same)`: nothing said. `None` is a version read that
///   failed; `Same` is two binaries reporting one version and still not
///   understanding each other, which means a signature changed without the
///   version being raised -- `porthole_core::ipc::SIGNATURE`'s two guards
///   exist to make that impossible to ship, and if it is somehow true here
///   then the version is not evidence about anything. Both get the wording
///   from before there was a version: both remedies, blaming neither.
///
/// No action button in any of them: the agent shows this on its way out, so
/// there would be nobody left to answer a click.
pub fn undecodable_notice(alignment: Option<Alignment>) -> Notification {
    // One opening for all three: what happened, and that this agent has
    // stopped rather than gone quiet, is the same fact whichever half is
    // old.
    let opening = "porthole-agent could not read a message the porthole helper sent, so it \
                   would have announced nothing at all from here on. It has stopped instead \
                   of staying silent.";
    let remedy = match alignment {
        Some(Alignment::HelperIsOlder) => {
            "The porthole helper is the older of the two: it is still the one from before \
             the upgrade. Restart it — `systemctl restart porthole-helper.service` — and \
             then log out and back in to start this agent again."
        }
        Some(Alignment::ThisOneIsOlder) => {
            "This agent is the older of the two: the porthole helper speaks a newer version \
             of porthole than the porthole-agent installed on this machine. Reinstall \
             porthole, or finish the upgrade that was interrupted, and log out and back in."
        }
        Some(Alignment::Same) | None => {
            "The two are from different versions of porthole: log out and back in to start \
             the agent that is installed now, and if closes are still not announced, \
             restart porthole-helper.service — that is the half left over from before the \
             upgrade."
        }
    };
    Notification {
        summary: "Porthole notifications stopped".to_string(),
        body: format!("{opening} {remedy}"),
        actions: Vec::new(),
    }
}

/// Show one, and hand back the id the server gave it.
///
/// The id is what ties a later `ActionInvoked` back to the rule this was
/// about; nothing else in this binary keeps a record of anything.
pub async fn show(proxy: &NotificationsProxy<'_>, n: &Notification) -> zbus::Result<u32> {
    proxy
        .notify(
            APP_NAME,
            NEW_NOTIFICATION,
            APP_ICON,
            &n.summary,
            &n.body,
            &n.action_pairs(),
            HashMap::new(),
            SERVER_DEFAULT_TIMEOUT,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closed_rule(port: u16, protocol: &str) -> WireRule {
        WireRule {
            id: "abc".to_string(),
            port,
            protocol: protocol.to_string(),
            target: "10.10.10.0/24".to_string(),
            scope: "network".to_string(),
            backend: "firewalld".to_string(),
            opened_at: 1_757_000_000,
            expires_at: 1_757_003_600,
            uid: 1000,
            // Not a forward: an empty address is what says so.
            container_addr: String::new(),
            container_port: 0,
            published_port: 0,
        }
    }

    /// The only kind of rule `TargetGone` is ever sent for: one that
    /// redirects. `container_addr` non-empty is what says so on the wire.
    fn forward_rule(port: u16, published_port: u16) -> WireRule {
        WireRule {
            port,
            container_addr: "172.18.0.2".to_string(),
            container_port: 8080,
            published_port,
            ..closed_rule(port, "tcp")
        }
    }

    fn signal_from_uid(uid: u32) -> WireRule {
        WireRule {
            uid,
            ..closed_rule(5173, "tcp")
        }
    }

    #[test]
    fn an_expiry_notification_says_what_closed_and_why() {
        let n = notification_for(&closed_rule(5173, "tcp"), CloseReason::Expired);
        assert!(n.body.contains("5173/tcp"), "{}", n.body);
        assert!(n.body.contains("expired"), "{}", n.body);
    }

    #[test]
    fn an_expiry_offers_reopen_but_a_network_change_does_not() {
        // Reopening after an expiry restores what the user wanted. Reopening
        // after a network change would re-create a rule for a subnet the
        // machine has left -- the action would appear to work and achieve
        // nothing.
        let r = closed_rule(5173, "tcp");
        assert!(notification_for(&r, CloseReason::Expired)
            .actions
            .iter()
            .any(|a| a.0 == "reopen"));
        assert!(notification_for(&r, CloseReason::NetworkChanged)
            .actions
            .is_empty());
    }

    #[test]
    fn every_reason_a_forward_reaches_says_it_was_a_redirect() {
        // Told only "8443/tcp towards 10.10.10.0/24 has expired", or "was
        // open towards 10.10.10.0/24, a network this machine is no longer
        // on", a person believes traffic was being let through to something
        // on this machine when it was being redirected into a container.
        // `porthole-gui`'s `open_now.rs` was changed to stop making exactly
        // this collapse on the row; the notification beside the button made
        // it too, and for a while it was repaired for `Expired` alone while
        // the other three arms went on making it.
        //
        // All four reasons a rule of either kind can reach, in one loop, so
        // a fifth arm added to the enum cannot be written as an open by
        // being written somewhere this test does not look.
        let permit = closed_rule(5173, "tcp");
        let forward = forward_rule(8443, 3000);

        for reason in [
            CloseReason::Expired,
            CloseReason::NetworkChanged,
            CloseReason::Reconciled,
            CloseReason::Requested,
        ] {
            let plain = notification_for(&permit, reason);
            let redirected = notification_for(&forward, reason);

            assert!(
                redirected.body.contains("redirect"),
                "{reason:?}: a forward must say it redirected: {}",
                redirected.body
            );
            assert!(
                redirected.body.contains("3000"),
                "{reason:?}: and name the published port it redirected to, which is \
                 the number the person knows the service by: {}",
                redirected.body
            );
            assert!(
                !plain.body.contains("redirect"),
                "{reason:?}: a rule that only permitted must claim no redirect: {}",
                plain.body
            );
            assert!(
                !plain.body.contains("3000"),
                "{reason:?}: and must name no container's port: {}",
                plain.body
            );
            // Each still says the thing its own notification is for: this
            // changed which act is named, not what happened.
            let own_words = match reason {
                CloseReason::Expired => "expired",
                CloseReason::NetworkChanged => "no longer on",
                CloseReason::Reconciled => "dropped its record",
                CloseReason::Requested => "on request",
                CloseReason::TargetGone => unreachable!("not in the loop above"),
            };
            for n in [&plain, &redirected] {
                assert!(n.body.contains(own_words), "{reason:?}: {}", n.body);
                assert!(n.body.contains("8443/tcp") || n.body.contains("5173/tcp"));
            }
        }

        // And the offer is unchanged by any of it: an expiry still carries
        // the button, both kinds of rule.
        for rule in [&permit, &forward] {
            assert!(notification_for(rule, CloseReason::Expired)
                .actions
                .iter()
                .any(|a| a.0 == REOPEN));
        }
    }

    #[test]
    fn a_gone_container_offers_reopen_and_a_network_change_still_does_not() {
        // Both halves, deliberately, in one check: the two reasons are
        // adjacent in the enum and share the shape of their notification,
        // and the temptation to "make them consistent" is exactly what this
        // exists to stop. They are not the same case. A forward's request
        // names a published port and the helper resolves the container
        // afresh every time it acts, so re-sending it finds the container
        // wherever it is now. A network-scoped rule's request names the
        // subnet itself, and nothing re-resolves that: reopening after a
        // network change would build a rule for a subnet this machine has
        // left, which would appear to work and reach nobody.
        let forward = forward_rule(8443, 3000);
        let gone = notification_for(&forward, CloseReason::TargetGone);
        assert!(
            gone.actions.iter().any(|a| a.0 == REOPEN),
            "a container that moved can be found again: {:?}",
            gone.actions
        );
        assert!(
            gone.body.contains("Reopening"),
            "the body must say what the button will do: {}",
            gone.body
        );

        assert!(
            notification_for(&forward, CloseReason::NetworkChanged)
                .actions
                .is_empty(),
            "a subnet this machine has left cannot be resolved afresh"
        );
        assert!(
            notification_for(&forward, CloseReason::Reconciled)
                .actions
                .is_empty(),
            "porthole must not argue at one click with whatever removed the rule"
        );
    }

    #[test]
    fn the_undecodable_notice_offers_both_remedies_when_nothing_said_which_half_is_old() {
        // The wording from before there was a version on the wire, and
        // still the right one whenever there is nothing to go on: a
        // signature mismatch names two signatures and does not order them,
        // so a notice that named one remedy would be right half the time
        // and would send the other half looking in the wrong place.
        //
        // `None` is a version read that failed -- which includes a helper
        // that has gone away between the failure and the question.
        let n = undecodable_notice(None);
        assert!(
            n.body.contains("Log out and back in") || n.body.contains("log out and back in"),
            "the agent's own remedy must be there: {}",
            n.body
        );
        assert!(
            n.body.contains("porthole-helper.service"),
            "and the helper's, since it may be the older half: {}",
            n.body
        );
        assert!(
            n.actions.is_empty(),
            "the agent is on its way out; a button would have nobody to answer it"
        );
        // And it must not read as the other notice: that one is about a
        // name a second process holds, which is a different thing to go
        // looking for.
        assert_ne!(n.summary, stale_agent_notice().summary);

        // Two binaries reporting the same version and still unable to read
        // each other means a signature moved without the version being
        // raised -- so the version is not evidence about anything, and this
        // must not name a half on the strength of it.
        assert_eq!(
            undecodable_notice(Some(Alignment::Same)).body,
            n.body,
            "an equal version that is nonetheless a mismatch says nothing about which \
             half is old, and the notice must not pretend otherwise"
        );
    }

    #[test]
    fn the_notice_names_the_one_remedy_the_version_identifies() {
        // The whole point of putting the version on the wire. Before it,
        // both of these read identically and the user had to try both.
        let helper_older = undecodable_notice(Some(Alignment::HelperIsOlder));
        assert!(
            helper_older
                .body
                .contains("systemctl restart porthole-helper.service"),
            "the helper's own version says it is the older half, so say so: {}",
            helper_older.body
        );
        assert!(
            !helper_older
                .body
                .contains("if closes are still not announced"),
            "and stop hedging between two remedies once one of them is known: {}",
            helper_older.body
        );

        let agent_older = undecodable_notice(Some(Alignment::ThisOneIsOlder));
        assert!(
            agent_older.body.contains("Reinstall porthole"),
            "an agent that could not replace itself has one thing left to say: {}",
            agent_older.body
        );
        assert!(
            !agent_older.body.contains("restart porthole-helper.service"),
            "the helper is the newer half here; restarting it would change nothing: {}",
            agent_older.body
        );

        // The three are three different sentences, not one sentence three
        // times: a notice that named the same remedy whatever the version
        // said would pass every assertion above that it happened to
        // contain.
        let unknown = undecodable_notice(None);
        assert_ne!(helper_older.body, agent_older.body);
        assert_ne!(helper_older.body, unknown.body);
        assert_ne!(agent_older.body, unknown.body);
        // And all three still say what happened, which is the half that
        // does not depend on any version.
        for n in [&helper_older, &agent_older, &unknown] {
            assert!(n.body.contains("could not read a message"), "{}", n.body);
            assert!(n.actions.is_empty());
            assert_eq!(n.summary, "Porthole notifications stopped");
        }
    }

    #[test]
    fn a_signal_for_another_user_is_ignored() {
        // The system bus broadcasts to every agent on the machine. Notifying
        // a second user about the first user's ports is noise, and hands
        // them a `Reopen` for a rule that is not theirs. The brief called it
        // a leak as well; `list` is authorized for every user, so it is not
        // one.
        assert!(should_notify(&signal_from_uid(1000), 1000));
        assert!(!should_notify(&signal_from_uid(1001), 1000));
    }

    #[test]
    fn a_reconciliation_is_announced_and_a_requested_close_is_not() {
        // The helper's start-up sweep announces what it dropped as soon as it
        // owns the bus name, and an agent that subscribed and then woke the
        // helper is listening by then -- so `reconciled` is an ordinary thing
        // to receive, not a start-up detail this can ignore. It says the port
        // had already stopped being open, which is the one thing that
        // separates it from the other three.
        assert!(is_worth_announcing(CloseReason::Reconciled));
        assert!(is_worth_announcing(CloseReason::Expired));
        assert!(is_worth_announcing(CloseReason::NetworkChanged));
        assert!(is_worth_announcing(CloseReason::TargetGone));
        assert!(!is_worth_announcing(CloseReason::Requested));

        let n = notification_for(&closed_rule(5173, "tcp"), CloseReason::Reconciled);
        assert!(n.body.contains("5173/tcp"), "{}", n.body);
        assert!(
            n.body.contains("Nothing was removed from the firewall"),
            "{}",
            n.body
        );
        assert!(n.actions.is_empty());
    }

    /// One document this binary is described to a person in, read from
    /// disk. Neither is compiled, so nothing else in this workspace notices
    /// when the code they describe changes underneath them -- which is
    /// exactly what happened: `TargetGone` gaining a `Reopen` made both of
    /// them false, and both were caught by a reviewer rather than by any
    /// check. The same coupling `tests/units.rs` keeps between this
    /// binary's `ExecStart=` and its install instructions.
    fn document(name: &str) -> String {
        let path = format!("{}/../../{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    /// The one `##` section of `text` that describes this binary, from its
    /// heading to the next one, whitespace collapsed.
    ///
    /// **The section, not the file, and that is not tidiness.** Both checks
    /// below were first written against whole documents, and their own
    /// negative controls exposed it: deleting the sentence that names
    /// `forward` among what a `Reopen` can send left the check green,
    /// because `docs/installing.md` says "`forward`" elsewhere; deleting
    /// "every time" left it green too, because the polkit table above says
    /// "asks every time" about a different action entirely. A guard that a
    /// nearby paragraph can satisfy is not guarding the paragraph it was
    /// written for.
    ///
    /// Whitespace is collapsed *after* slicing, and that is also load-
    /// bearing: both files are hard-wrapped prose, so a phrase looked for
    /// here is routinely split across a line break. The first run of the
    /// reason check failed on `"no longer had"` for exactly that -- the
    /// words present, a newline between them -- which is a guard a reader
    /// would otherwise have weakened rather than a defect in the document.
    fn section(text: &str, heading: &str) -> String {
        let start = text
            .find(heading)
            .unwrap_or_else(|| panic!("no section starting {heading:?}"));
        let body = &text[start + heading.len()..];
        let end = body.find("\n## ").unwrap_or(body.len());
        body[..end].split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// `docs/installing.md`'s account of this binary.
    fn installing_sections_on_the_agent() -> String {
        section(&document("docs/installing.md"), "## The agent")
    }

    /// `README.md`'s.
    fn readme_section_on_the_agent() -> String {
        section(&document("README.md"), "## Desktop notifications")
    }

    /// How each reason is named to a person, as opposed to how it is named
    /// on the wire.
    ///
    /// Exhaustive over the enum on purpose, exactly as `notification_for`
    /// is and for the same reason: a reason added to the wire has to come
    /// here and say what a reader is told about it, rather than being
    /// announced on screen and mentioned in no document at all.
    fn documented_as(reason: CloseReason) -> &'static str {
        match reason {
            CloseReason::Expired => "expiry",
            CloseReason::NetworkChanged => "network change",
            CloseReason::Reconciled => "no longer had",
            CloseReason::TargetGone => "no longer the one it was created against",
            // Not announced at all, so no document owes it an entry -- the
            // check below skips it through `is_worth_announcing`.
            CloseReason::Requested => "",
        }
    }

    #[test]
    fn both_documents_name_every_close_this_binary_announces() {
        // `README.md`'s "Desktop notifications" section and
        // `docs/installing.md`'s "The agent" section each enumerate what
        // this binary announces. Both enumerations were written when there
        // were three reasons and silently became wrong when there were
        // four.
        let readme = readme_section_on_the_agent();
        let installing = installing_sections_on_the_agent();
        for reason in [
            CloseReason::Expired,
            CloseReason::Requested,
            CloseReason::NetworkChanged,
            CloseReason::Reconciled,
            CloseReason::TargetGone,
        ] {
            if !is_worth_announcing(reason) {
                continue;
            }
            let phrase = documented_as(reason);
            assert!(
                readme.contains(phrase),
                "README.md never names the {reason} close (looked for {phrase:?})"
            );
            assert!(
                installing.contains(phrase),
                "docs/installing.md never names the {reason} close (looked for {phrase:?})"
            );
        }
    }

    #[test]
    fn the_install_document_still_states_the_whole_of_what_a_reopen_can_provoke() {
        // This one is a *security* statement, not a description: it is what
        // an administrator reads to learn the full extent of what this
        // unprivileged session agent can cause on the system bus. It said
        // the button "re-sends an ordinary `open` request" at a commit
        // where the button could already send a `forward` -- an
        // `auth_admin`-every-time operation -- so it understated the agent
        // to the one reader who most needed it not to be understated.
        //
        // What this pins is that both methods stay named, in that section,
        // and that the stronger authorization stays stated. It cannot
        // notice a *third* method appearing; `reopen`'s own `match` in
        // `main.rs` is where that would be added, and its two arms are what
        // these two names correspond to.
        let installing = installing_sections_on_the_agent();
        for method in ["`open`", "`forward`"] {
            assert!(
                installing.contains(method),
                "docs/installing.md's agent section must name {method} among what a Reopen \
                 can send"
            );
        }
        assert!(
            installing.contains("every time"),
            "docs/installing.md's agent section must say a forward is authorized every \
             time, whatever its scope: that is what makes the agent's reach worth stating \
             at all"
        );
    }

    #[test]
    fn every_notification_names_the_port_and_pairs_its_actions() {
        for reason in [
            CloseReason::Expired,
            CloseReason::Requested,
            CloseReason::NetworkChanged,
            CloseReason::Reconciled,
            CloseReason::TargetGone,
        ] {
            let n = notification_for(&closed_rule(8080, "udp"), reason);
            assert!(n.body.contains("8080/udp"), "{reason}: {}", n.body);
            assert!(!n.summary.is_empty(), "{reason}");
            // `Notify` takes actions as one flat list, key before label.
            // Flattened the other way round it is still the right length and
            // still even, and every server would show `reopen` as the button
            // text and send `Reopen` back as the key -- which no branch here
            // acts on.
            for pair in n.action_pairs().chunks(2) {
                assert_eq!(pair.len(), 2, "{reason}: a key with no label");
                assert_eq!(
                    pair[0], REOPEN,
                    "{reason}: the key comes first, and it is what `ActionInvoked` sends back"
                );
                assert_ne!(pair[1], REOPEN, "{reason}: the label is not the key");
            }
        }
    }
}
