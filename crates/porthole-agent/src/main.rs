//! porthole's session half: the thing that tells the user a port closed.
//!
//! The helper is a system service and cannot comfortably reach a user's
//! session bus. By the time a port expires or the machine leaves the network
//! a rule was scoped to, the window that opened it is almost always gone --
//! so without something listening in the session, a close that nobody asked
//! for is announced to nobody.
//!
//! One job, and no interface of its own: listen on the **system** bus for
//! `RuleClosed`, and call `org.freedesktop.Notifications` on the **session**
//! bus. It serves no object and holds no view of what is open -- `list` is
//! the authority for that, and this never shows a list. The only thing it
//! remembers is which notification was about which rule, so a `Reopen` click
//! has something to re-send (see [`Pending`]).
//!
//! It does own one session-bus name, and only to refuse to be started twice.
//! porthole ships both a systemd user unit and an XDG autostart entry,
//! because desktops differ in which they honour, and a desktop that honours
//! both would otherwise show every close twice. Whichever copy loses the
//! name says so and exits.
//!
//! # Order of operations at start-up, and why it is that order
//!
//! Subscribe first, then wake the helper. A signal sent before a subscriber's
//! match rule exists is simply gone, and the helper's start-up sweep
//! announces what it dropped as soon as it owns the bus name. The helper is
//! D-Bus activated, so the very act of calling it is what starts it: an agent
//! that subscribes and *then* calls receives that sweep's announcements,
//! while one that calls first can lose them. The `list` call below is made
//! for that ordering alone -- its answer is not kept.
//!
//! # What is proven, and what is not
//!
//! `tests/session.rs` drives this binary over a private session bus against a
//! stand-in notification service and a stand-in helper: a close notifies, a
//! close belonging to another uid does not, a `Reopen` click re-sends the
//! original `open` with the original duration, and a bus with no notification
//! service at all leaves the process running. What none of that touches is a
//! real notification daemon (the stand-in answers `Notify` and emits
//! `ActionInvoked`, it does not draw anything), the real helper, or polkit --
//! so "the prompt appears and the port comes back" is not covered by any test
//! in this repository.

mod notify;

use futures_util::StreamExt;
use notify::{NotificationsProxy, REOPEN};
use porthole_core::ipc::{PortholeProxy, WireRule};

/// The session-bus name one agent per session holds. Not an interface: this
/// process serves nothing, and the name exists only so a second copy can
/// discover it is a second copy. Deliberately not the helper's own
/// `com.jacopobriccola.Porthole`, which is a system-bus name owned by
/// something else entirely.
const AGENT_SERVICE: &str = "com.jacopobriccola.PortholeAgent";

/// How many notifications can be waiting for a click at once.
///
/// Each entry is one rule kept alive only so a `Reopen` on its notification
/// has something to re-send. Entries leave when the notification closes,
/// which is the ordinary case; the bound is what happens when a server never
/// says so. Past it, the oldest is dropped and a click on that notification
/// is refused with a line in the journal rather than acted on with a guess.
const MAX_PENDING: usize = 32;

/// The rules whose notifications are still on screen, oldest first.
///
/// A `Vec` rather than a map: it holds at most [`MAX_PENDING`] entries, a
/// click scans it once, and this way "oldest" is a position rather than an
/// assumption about how a notification server numbers things.
type Pending = Vec<(u32, WireRule)>;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let uid = current_uid();

    let session = match zbus::Connection::session().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("porthole-agent: no session bus, so nothing to notify on: {e}");
            return;
        }
    };
    // First, and before anything is woken or subscribed to: a second agent
    // in one session would show every close twice.
    if !claim_session(&session).await {
        return;
    }

    let system = match zbus::Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("porthole-agent: no system bus, so nothing to listen to: {e}");
            return;
        }
    };
    let porthole = match PortholeProxy::new(&system).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("porthole-agent: could not bind the helper's interface: {e}");
            return;
        }
    };
    // Awaited here, before the `list` below: this is the call that installs
    // the match rule, and the ordering above is the whole point of it.
    let mut closes = match porthole.receive_rule_closed().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("porthole-agent: could not subscribe to the helper's signals: {e}");
            return;
        }
    };

    let notifications = match NotificationsProxy::new(&session).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("porthole-agent: could not bind the notification interface: {e}");
            return;
        }
    };
    let (mut actions, mut dismissals) = match (
        notifications.receive_action_invoked().await,
        notifications.receive_notification_closed().await,
    ) {
        (Ok(a), Ok(d)) => (a, d),
        (a, d) => {
            let e = a.err().or(d.err()).expect("one of the two failed");
            eprintln!("porthole-agent: could not subscribe to notification actions: {e}");
            return;
        }
    };

    // Not for its answer. Calling the helper is what starts it, and the
    // subscription above already exists, so whatever its start-up sweep
    // announces arrives here instead of being sent to nobody. A failure is
    // ordinary -- no helper installed, or none activatable -- and changes
    // nothing about what this process does next.
    if let Err(e) = porthole.list().await {
        eprintln!("porthole-agent: could not reach the helper ({e}); listening anyway");
    }

    eprintln!("porthole-agent: listening for uid {uid}");

    let mut pending: Pending = Vec::new();
    loop {
        tokio::select! {
            Some(signal) = closes.next() => {
                let Ok(args) = signal.args() else { continue };
                on_close(&notifications, &mut pending, args.rule(), *args.reason(), uid).await;
            }
            Some(signal) = actions.next() => {
                let Ok(args) = signal.args() else { continue };
                on_action(&porthole, &notifications, &pending, args.id, args.action_key);
            }
            Some(signal) = dismissals.next() => {
                let Ok(args) = signal.args() else { continue };
                pending.retain(|(id, _)| *id != args.id);
            }
            else => break,
        }
    }

    // Every stream ended at once, which means the connections behind them
    // are gone. There is nothing left to listen to, and nothing here can put
    // them back.
    eprintln!("porthole-agent: the bus connections ended; stopping");
}

/// One `RuleClosed`.
async fn on_close(
    notifications: &NotificationsProxy<'_>,
    pending: &mut Pending,
    rule: &WireRule,
    reason: porthole_core::ipc::CloseReason,
    uid: u32,
) {
    if !notify::should_notify(rule, uid) || !notify::is_worth_announcing(reason) {
        return;
    }
    let n = notify::notification_for(rule, reason);
    match notify::show(notifications, &n).await {
        Ok(id) => {
            // The only record that a close was actually announced to
            // somebody. A `Notify` that returns an id has been accepted by a
            // server; what the server then did with it is not visible here.
            eprintln!(
                "porthole-agent: notified about {}/{} ({reason}) as #{id}",
                rule.port, rule.protocol
            );
            if !n.actions.is_empty() {
                if pending.len() >= MAX_PENDING {
                    pending.remove(0);
                }
                pending.push((id, rule.clone()));
            }
        }
        // The one failure this must survive rather than report: a session
        // with no notification service answers every `Notify` this way, and
        // a user unit that gave up here would be restarted into the same
        // session to fail again. The journal still records what closed.
        Err(e) => eprintln!(
            "porthole-agent: {}/{} closed ({reason}) but could not be shown: {e}",
            rule.port, rule.protocol
        ),
    }
}

/// One `ActionInvoked`.
///
/// Spawned rather than awaited: `open` goes through polkit, which can sit on
/// a password prompt for as long as the user takes to answer it, and the
/// signal loop must keep reading meanwhile.
fn on_action(
    porthole: &PortholeProxy<'static>,
    notifications: &NotificationsProxy<'static>,
    pending: &Pending,
    id: u32,
    key: &str,
) {
    if key != REOPEN {
        return;
    }
    let Some((_, rule)) = pending.iter().find(|(pending_id, _)| *pending_id == id) else {
        eprintln!("porthole-agent: a reopen arrived for a notification this no longer holds");
        return;
    };
    let porthole = porthole.clone();
    let notifications = notifications.clone();
    let rule = rule.clone();
    tokio::spawn(async move { reopen(porthole, notifications, rule).await });
}

/// Re-send the original `open`: the same port, the same protocol, the same
/// scope, and the same length of time.
///
/// polkit will ask again where the scope warrants it. That is the point of
/// polkit asking, not an obstacle: this is a fresh request to open a port,
/// made because someone clicked a button, and it is authorized as one.
async fn reopen(
    porthole: PortholeProxy<'static>,
    notifications: NotificationsProxy<'_>,
    rule: WireRule,
) {
    let scope = reopen_scope(&rule);
    let seconds = original_duration(&rule);
    match porthole
        .open(rule.port, &rule.protocol, &scope, seconds)
        .await
    {
        Ok(reopened) => eprintln!(
            "porthole-agent: reopened {}/{} towards {}",
            reopened.port, reopened.protocol, reopened.target
        ),
        Err(e) => {
            let failure = notify::Notification {
                summary: format!("Could not reopen port {}/{}", rule.port, rule.protocol),
                body: format!("{e}"),
                actions: Vec::new(),
            };
            if let Err(e2) = notify::show(&notifications, &failure).await {
                eprintln!("porthole-agent: reopen failed ({e}), and so did saying so ({e2})");
            }
        }
    }
}

/// The scope string the helper's own parser takes, rebuilt from the rule.
///
/// A `network` rule carries its CIDR, which parses back to exactly itself --
/// including a single host, which is stored as a `/32`. An `anywhere` rule's
/// target renders as the word `anywhere`, and that is not a spelling the
/// parser accepts: `any` is.
fn reopen_scope(rule: &WireRule) -> String {
    if rule.scope == "anywhere" {
        "any".to_string()
    } else {
        rule.target.clone()
    }
}

/// How long the rule was opened for -- not the moment it would have ended.
///
/// `0` means until-reboot in both directions: on the wire it is
/// `expires_at`'s "no expiry" sentinel, and in `open`'s `seconds` it is the
/// until-reboot lifetime. A rule whose recorded expiry precedes its own
/// opening cannot produce a negative duration here; it produces zero, which
/// is the until-reboot request, so the saturation is spelled out rather than
/// left to wrap.
fn original_duration(rule: &WireRule) -> u32 {
    if rule.expires_at == 0 {
        return 0;
    }
    u32::try_from(rule.expires_at.saturating_sub(rule.opened_at)).unwrap_or(u32::MAX)
}

/// Take the session-bus name that means "this session already has an agent",
/// or report that somebody else has it.
///
/// `DoNotQueue` rather than the default: a second agent must find out now and
/// stop, not sit in a queue waiting to inherit the name if the first one ever
/// exits, quietly turning into a live second agent later.
///
/// Anything other than becoming the primary owner is a reason to stop, and
/// that includes a bus that refuses the request outright -- there is no
/// reading of either outcome under which starting a second notifier is the
/// better answer.
async fn claim_session(session: &zbus::Connection) -> bool {
    use zbus::fdo::{RequestNameFlags, RequestNameReply};
    match session
        .request_name_with_flags(AGENT_SERVICE, RequestNameFlags::DoNotQueue.into())
        .await
    {
        Ok(RequestNameReply::PrimaryOwner) => true,
        // Measured rather than assumed: with `DoNotQueue`, this zbus reports
        // a name somebody else holds as `Error::NameTaken` and not as one of
        // the other replies. Both readings say the same thing, so both are
        // handled here rather than one of them falling through to the
        // catch-all below and being reported as a bus failure.
        Ok(_) | Err(zbus::Error::NameTaken) => {
            eprintln!(
                "porthole-agent: this session already has an agent ({AGENT_SERVICE} is taken); \
                 stopping so closes are not announced twice"
            );
            false
        }
        Err(e) => {
            eprintln!("porthole-agent: could not claim {AGENT_SERVICE}, so stopping: {e}");
            false
        }
    }
}

fn current_uid() -> u32 {
    // SAFETY: getuid takes no arguments, touches no memory, and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(scope: &str, target: &str, opened_at: u64, expires_at: u64) -> WireRule {
        WireRule {
            id: "abc".to_string(),
            port: 5173,
            protocol: "tcp".to_string(),
            target: target.to_string(),
            scope: scope.to_string(),
            backend: "firewalld".to_string(),
            opened_at,
            expires_at,
            uid: 1000,
        }
    }

    #[test]
    fn a_reopen_sends_the_scope_the_helpers_parser_accepts() {
        // The wire form renders `Target::Anywhere` as the word `anywhere`,
        // and `porthole_core::validate::parse_scope` does not take that word.
        // Sending it back verbatim would turn every reopen of an open-to-
        // everyone rule into an invalid-argument error.
        assert_eq!(reopen_scope(&rule("anywhere", "anywhere", 0, 0)), "any");
        assert_eq!(
            reopen_scope(&rule("network", "10.10.10.0/24", 0, 0)),
            "10.10.10.0/24"
        );
        assert_eq!(
            reopen_scope(&rule("network", "10.10.10.5/32", 0, 0)),
            "10.10.10.5/32"
        );
    }

    #[test]
    fn a_reopen_sends_the_original_duration_not_the_original_deadline() {
        // An hour-long rule reopens for an hour, whenever it is clicked --
        // not until the instant the first one would have ended, which is in
        // the past by the time the notification is on screen.
        assert_eq!(
            original_duration(&rule(
                "network",
                "10.10.10.0/24",
                1_757_000_000,
                1_757_003_600
            )),
            3600
        );
        assert_eq!(
            original_duration(&rule("network", "10.10.10.0/24", 1_757_000_000, 0)),
            0,
            "0 is until-reboot on the wire and until-reboot in the request"
        );
        assert_eq!(
            original_duration(&rule(
                "network",
                "10.10.10.0/24",
                1_757_003_600,
                1_757_000_000
            )),
            0,
            "an expiry before its own opening asks for nothing, never a wrapped duration"
        );
    }
}
