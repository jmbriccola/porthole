//! What a closed rule looks like as a desktop notification, and the session
//! bus interface that shows one.
//!
//! Everything that decides *what* to say is a plain function over a
//! [`WireRule`] and a [`CloseReason`], with no bus anywhere near it, so the
//! wording and the filtering are testable without a notification daemon. Only
//! [`NotificationsProxy`] and [`show`] touch the session bus.

use porthole_core::ipc::{CloseReason, WireRule};
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
    let target = &rule.target;
    match reason {
        CloseReason::Expired => Notification {
            summary: format!("Port {port} closed"),
            body: format!("{port} towards {target} has expired and is closed again."),
            actions: vec![(REOPEN.to_string(), "Reopen".to_string())],
        },
        CloseReason::NetworkChanged => Notification {
            summary: format!("Port {port} closed"),
            body: format!(
                "{port} was open towards {target}, a network this machine is no longer on, \
                 so porthole closed it."
            ),
            actions: Vec::new(),
        },
        CloseReason::Reconciled => Notification {
            summary: format!("Port {port} was already closed"),
            body: format!(
                "{port} towards {target} had stopped being open before porthole looked: the \
                 firewall no longer had the rule, so porthole dropped its record of it. \
                 Nothing was removed from the firewall."
            ),
            actions: Vec::new(),
        },
        CloseReason::Requested => Notification {
            summary: format!("Port {port} closed"),
            body: format!("{port} towards {target} was closed on request."),
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
